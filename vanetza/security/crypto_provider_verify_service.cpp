#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <boost/optional.hpp>
#include <boost/variant/get.hpp>
#include <algorithm>

// asn1c quirk
struct Vanetza_Security_Certificate : public Vanetza_Security_CertificateBase {};

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

// verifies signature of a hash calculated by algorithm of given digest type
template<typename Digest>
expected<bool> verify_digest(
    CryptoProvider& crypto, const ByteBuffer& hash, const Signature& signature, const PublicKey& key)
{
    Digest digest;
    if (hash.size() != digest.octets.size()) {
        return false;
    }
    std::copy(hash.begin(), hash.end(), digest.octets.begin());
    return crypto.verify(digest, signature, key);
}

// verifies signature of a hash calculated by given algorithm, false for unsupported algorithms
expected<bool> verify_hash(CryptoProvider& crypto, HashAlgorithm algo, const ByteBuffer& hash,
    const Signature& signature, const PublicKey& key)
{
    switch (algo) {
        case HashAlgorithm::SHA256:
            return verify_digest<Sha256Hash>(crypto, hash, signature, key);
        case HashAlgorithm::SHA384:
            return verify_digest<Sha384Hash>(crypto, hash, signature, key);
        default:
            return false;
    }
}

// certificate included as signer identifier, nullptr for a digest
const asn1::Certificate* included_certificate(const SecuredMessage::SignerIdentifier& signer)
{
    const asn1::Certificate* const* certificate = boost::get<const asn1::Certificate*>(&signer);
    return certificate ? *certificate : nullptr;
}

void reject_certificate(VerifyConfirm& confirm, CertificateInvalidReason reason)
{
    confirm.report = VerificationReport::Invalid_Certificate;
    confirm.certificate_validity = reason;
}

// checks issuer's signature of a ticket (IEEE 1609.2 clause 5.3.1), false if confirm reports its rejection
bool check_issuer_signature(
    CryptoProvider& crypto, const asn1::Certificate& ticket, const Certificate& issuer, VerifyConfirm& confirm)
{
    if (!ticket.signature) {
        reject_certificate(confirm, CertificateInvalidReason::Missing_Signature);
        return false;
    }

    const boost::optional<Signature> signature = get_signature(ticket);
    const boost::optional<PublicKey> issuer_key = get_public_key(*issuer.content());
    if (!signature || !issuer_key) {
        reject_certificate(confirm, CertificateInvalidReason::Invalid_Signer);
        return false;
    }

    const HashAlgorithm algo = specified_hash_algorithm(issuer_key->type);
    const ByteBuffer hash = calculate_certificate_hash(crypto, algo, CertificateView { &ticket }, issuer);
    if (hash.empty()) {
        // malformed certificates failing their canonical encoding
        confirm.report = VerificationReport::Incompatible_Protocol;
        return false;
    }

    const expected<bool> verified = verify_hash(crypto, algo, hash, *signature, *issuer_key);
    if (verified.has_value() && *verified) {
        return true;
    } else if (verified.has_value()) {
        reject_certificate(confirm, CertificateInvalidReason::Invalid_Signer);
    } else if (verified.error() == SecurityModuleError::UnsupportedKeyType) {
        confirm.report = VerificationReport::Incompatible_Protocol;
    } else {
        // e.g. an unusable key of a trusted issuer, i.e. of the station's trust information
        confirm.report = VerificationReport::Configuration_Problem;
    }
    return false;
}

// finds a ticket's issuer among the trusted ones, nullptr if confirm reports the ticket's rejection
const Certificate* find_trusted_issuer(const IssuerLookup& issuers, const asn1::Certificate& ticket,
    VerifyConfirm& confirm)
{
    const CertificateView view { &ticket };
    const boost::optional<HashedId8> issuer_id = view.issuer_digest();
    const Certificate* issuer = issuer_id ? issuers.find_issuer(*issuer_id) : nullptr;
    if (view.issuer_is_self()) {
        // tickets are issued by an AA, they are never self-signed
        reject_certificate(confirm, CertificateInvalidReason::Invalid_Signer);
    } else if (!issuer_id) {
        // issuer identifier is unsupported
        confirm.report = VerificationReport::Incompatible_Protocol;
    } else if (!issuer) {
        // issuer is unknown or not trusted anymore, e.g. revoked meanwhile
        reject_certificate(confirm, CertificateInvalidReason::Unknown_Signer);
    }
    return issuer;
}

// verifies a message's signature by its signer's public key
VerificationReport verify_signature(CryptoProvider& crypto, const SecuredMessage& msg,
    const asn1::Certificate& signer, const Signature& signature, const PublicKey& key)
{
    vanetza::asn1::asn1c_error error;
    const ByteBuffer payload = msg.signing_payload(error);
    if (error) {
        // malformed message failing its encoding
        return VerificationReport::Incompatible_Protocol;
    }

    const ByteBuffer hash = calculate_message_hash(crypto, msg.hash_id(), payload, CertificateView { &signer });
    if (hash.empty()) {
        // unsupported hash algorithm or a signer certificate without encodable canonical form
        return VerificationReport::Incompatible_Protocol;
    }

    const expected<bool> verified = verify_hash(crypto, msg.hash_id(), hash, signature, key);
    if (verified.has_value()) {
        return *verified ? VerificationReport::Success : VerificationReport::False_Signature;
    } else if (verified.error() == SecurityModuleError::UnsupportedKeyType) {
        return VerificationReport::Incompatible_Protocol;
    } else if (verified.error() == SecurityModuleError::InvalidPublicKey) {
        // signer's ticket carries an unusable key
        return VerificationReport::Invalid_Certificate;
    } else {
        return VerificationReport::Configuration_Problem;
    }
}

// enqueues certificates requested by a CAM and discards requests answered by it (peer-to-peer distribution)
void handle_p2pcd_requests(const SecuredMessage& msg, SignHeaderPolicy& policy)
{
    const auto& header = msg->content->choice.signedData->tbsData->headerInfo;
    if (header.inlineP2pcdRequest) {
        for (int i = 0; i < header.inlineP2pcdRequest->list.count; ++i) {
            policy.enqueue_p2p_request(create_hashed_id3(*header.inlineP2pcdRequest->list.array[i]));
        }
    }

    if (header.requestedCertificate) {
        const boost::optional<HashedId8> digest = calculate_digest(*header.requestedCertificate);
        if (digest) {
            policy.discard_p2p_request(truncate(*digest));
        }
    }
}

} // namespace
} // namespace v3

CryptoProviderVerifyService::CryptoProviderVerifyService(CryptoProvider& crypto, const v3::IssuerLookup* issuers) :
    m_crypto(crypto), m_issuers(issuers)
{
}

void CryptoProviderVerifyService::use_certificate_cache(v3::CertificateCache* cache)
{
    m_context_v3.m_cert_cache = cache;
}

void CryptoProviderVerifyService::use_certificate_validator(v3::CertificateValidator* validator)
{
    m_context_v3.m_cert_validator = validator;
}

void CryptoProviderVerifyService::use_sign_header_policy(v3::SignHeaderPolicy* policy)
{
    m_context_v3.m_sign_policy = policy;
}

VerifyConfirm CryptoProviderVerifyService::verify(const VerifyRequest& request)
{
    struct visitor : public boost::static_visitor<VerifyConfirm>
    {
        explicit visitor(CryptoProviderVerifyService& service) : m_service(service)
        {
        }

        VerifyConfirm operator()(const v2::SecuredMessage&) const
        {
            VerifyConfirm confirm;
            confirm.report = VerificationReport::Incompatible_Protocol;
            return confirm;
        }

        VerifyConfirm operator()(const v3::SecuredMessage& msg) const
        {
            return m_service.verify(msg);
        }

        CryptoProviderVerifyService& m_service;
    } visitor(*this);

    return boost::apply_visitor(visitor, request.secured_message);
}

VerifyConfirm CryptoProviderVerifyService::verify(const v3::SecuredMessage& msg)
{
    using namespace v3;
    /*
     * TS 103 097 v1.3.1 demands to assess the validity of signed data
     * according to IEEE 1609.2 clause 5.2.
     */
    VerifyConfirm confirm;
    confirm.report = VerificationReport::Incompatible_Protocol; /*< fallback error code */

    if (!msg.is_signed()) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (msg.protocol_version() != 3) {
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }

    auto gen_time = msg.generation_time();
    if (!gen_time) {
        // TS 103 097 v1.3.1 demands generation time to be always present
        confirm.report = VerificationReport::Invalid_Timestamp;
        return confirm;
    }
    // TODO further generation time checks depending on application profile

    auto signature = msg.signature();
    if (!signature) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    auto signer_identifier = msg.signer_identifier();

    // track "known" stations
    auto maybe_digest = get_certificate_id(signer_identifier);
    if (m_context_v3.m_cert_cache && maybe_digest) {
        bool was_unknown_station = m_context_v3.m_cert_cache->announce(*maybe_digest);
        if (was_unknown_station && msg.its_aid() == aid::CA && m_context_v3.m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_context_v3.m_sign_policy->request_certificate();
        }
    }

    if (msg.its_aid() == aid::CA && m_context_v3.m_sign_policy) {
        handle_p2pcd_requests(msg, *m_context_v3.m_sign_policy);
    }

    // tickets of the cache are verified, thus a ticket included again is taken from the cache
    const Certificate* cached =
        m_context_v3.m_cert_cache && maybe_digest ? m_context_v3.m_cert_cache->lookup(*maybe_digest) : nullptr;
    const asn1::Certificate* certificate = cached ? cached->content() : included_certificate(signer_identifier);
    if (!certificate) {
        if (msg.its_aid() == aid::CA && m_context_v3.m_sign_policy && maybe_digest) {
            // for received CAMs (having digest as signer identifier) with unknown AT we request the full AT certificate
            m_context_v3.m_sign_policy->request_unrecognized_certificate(*maybe_digest);
        }
        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        return confirm;
    }

    // code below can safely dereference certificate
    assert(certificate != nullptr);

    // check AT certificate's validity
    if (m_context_v3.m_cert_validator) {
        auto verdict = m_context_v3.m_cert_validator->valid_for_signing(CertificateView { certificate }, msg.its_aid());
        if (verdict != CertificateValidator::Verdict::Valid) {
            confirm.report = VerificationReport::Invalid_Certificate;
            return confirm;
        }
    }

    const boost::optional<HashedId8> aa_digest = CertificateView { certificate }.issuer_digest();
    if (aa_digest && m_context_v3.m_cert_cache && m_context_v3.m_sign_policy &&
        !m_context_v3.m_cert_cache->is_known(*aa_digest)) {
        // request unknown AA certificate for any received message signed with AT issued by this AA
        m_context_v3.m_sign_policy->request_unrecognized_certificate(*aa_digest);
    }
    // TODO: if AA is validated and fails, announce it in cache

    auto public_key = get_public_key(*certificate);
    if (!public_key) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
        return confirm;
    }

    if (m_issuers) {
        const Certificate* issuer = find_trusted_issuer(*m_issuers, *certificate, confirm);
        if (!issuer) {
            return confirm;
        }
        // tickets of the cache have been verified before they were cached
        if (!cached && !check_issuer_signature(m_crypto, *certificate, *issuer, confirm)) {
            return confirm;
        }
    }

    confirm.report = verify_signature(m_crypto, msg, *certificate, *signature, *public_key);
    if (confirm.report != VerificationReport::Success) {
        return confirm;
    }

    confirm.its_aid = msg.its_aid();
    confirm.permissions = get_app_permissions(*certificate, confirm.its_aid);
    confirm.certificate_id = maybe_digest;

    if (m_context_v3.m_cert_cache && confirm.certificate_id) {
        bool already_cached = m_context_v3.m_cert_cache->lookup(*confirm.certificate_id) != nullptr;
        if (!already_cached && confirm.its_aid == aid::CA && m_context_v3.m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_context_v3.m_sign_policy->request_certificate();
        }

        // update certificate cache with received certificate
        if (contains_certificate(signer_identifier)) {
            m_context_v3.m_cert_cache->store(Certificate { *certificate });
        }
    }

    return confirm;
}

} // namespace security
} // namespace vanetza
