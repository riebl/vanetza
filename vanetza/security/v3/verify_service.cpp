#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/verify_service.hpp>
#include <boost/optional.hpp>
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

// verifies signature of a message hash calculated by algorithm of given digest type
template<typename Digest>
expected<bool> verify_message_hash(
    CryptoProvider& crypto, const ByteBuffer& hash, const Signature& signature, const PublicKey& key)
{
    Digest digest;
    if (hash.size() != digest.octets.size()) {
        return false;
    }
    std::copy(hash.begin(), hash.end(), digest.octets.begin());
    return crypto.verify(digest, signature, key);
}

} // namespace

CryptoProviderVerifyService::CryptoProviderVerifyService(CryptoProvider& crypto) : m_crypto(crypto)
{
}

void CryptoProviderVerifyService::use_certificate_cache(CertificateCache* cache)
{
    m_cert_cache = cache;
}

void CryptoProviderVerifyService::use_certificate_validator(CertificateValidator* validator)
{
    m_cert_validator = validator;
}

void CryptoProviderVerifyService::use_sign_header_policy(SignHeaderPolicy* policy)
{
    m_sign_policy = policy;
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

        VerifyConfirm operator()(const SecuredMessage& msg) const
        {
            return m_service.verify(msg);
        }

        CryptoProviderVerifyService& m_service;
    } visitor(*this);

    return boost::apply_visitor(visitor, request.secured_message);
}

VerifyConfirm CryptoProviderVerifyService::verify(const SecuredMessage& msg)
{
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

    struct certificate_lookup_visitor : public boost::static_visitor<const asn1::Certificate*> {
        explicit certificate_lookup_visitor(CertificateCache* cache) :
            m_cache(cache)
        {
        }

        const asn1::Certificate* operator()(const asn1::HashedId8* digest) const
        {
            // look up certificate matching digest in local storage
            if (m_cache && digest) {
                const Certificate* found = m_cache->lookup(convert(*digest));
                return found ? found->content() : nullptr;
            } else {
                return nullptr;
            }
        }

        const asn1::Certificate* operator()(const asn1::Certificate* cert) const
        {
            return cert;
        }

        CertificateCache* m_cache;
    } certificate_lookup_visitor(m_cert_cache);
    auto signer_identifier = msg.signer_identifier();

    // track "known" stations
    auto maybe_digest = get_certificate_id(signer_identifier);
    if (m_cert_cache && maybe_digest) {
        bool was_unknown_station = m_cert_cache->announce(*maybe_digest);
        if (was_unknown_station && msg.its_aid() == aid::CA && m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_sign_policy->request_certificate();
        }
    }

    // check if a ITS-AID 36 (CAM) with inline cert request shall be handled by us
    if (msg.its_aid() == aid::CA && m_sign_policy) {
        Vanetza_Security_SequenceOfHashedId3* requests =
            msg->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest;
        if (requests) {
            for (int i = 0; i < requests->list.count; ++i)
            {
                const Vanetza_Security_HashedId3_t* req_digest = requests->list.array[i];
                const HashedId3 hid3 = create_hashed_id3(*req_digest);
                m_sign_policy->enqueue_p2p_request(hid3);
            }
        }

        Vanetza_Security_Certificate* included_cert =
            msg->content->choice.signedData->tbsData->headerInfo.requestedCertificate;
        if (included_cert) {
            auto maybe_digest = calculate_digest(*included_cert);
            if (maybe_digest) {
                m_sign_policy->discard_p2p_request(truncate(*maybe_digest));
            }
        }
    }

    const asn1::Certificate* certificate = boost::apply_visitor(certificate_lookup_visitor, signer_identifier);
    if (!certificate) {
        if (msg.its_aid() == aid::CA && m_sign_policy && maybe_digest) {
            // for received CAMs (having digest as signer identifier) with unknown AT we request the full AT certificate
            m_sign_policy->request_unrecognized_certificate(*maybe_digest);
        }
        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        return confirm;
    }

    // code below can safely dereference certificate
    assert(certificate != nullptr);

    // check AT certificate's validity
    if (m_cert_validator) {
        auto verdict = m_cert_validator->valid_for_signing(CertificateView { certificate }, msg.its_aid());
        if (verdict != CertificateValidator::Verdict::Valid) {
            confirm.report = VerificationReport::Invalid_Certificate;
            return confirm;
        }
    }

    boost::optional<HashedId8> aa_digest;
    switch (certificate->issuer.present)
    {
        case Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest:
            aa_digest = convert(certificate->issuer.choice.sha256AndDigest);
            break;
        case Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest:
            aa_digest = convert(certificate->issuer.choice.sha384AndDigest);
            break;
        default:
            break;
    }

    if (aa_digest && m_cert_cache) {
        if (!m_cert_cache->is_known(*aa_digest)) {
            if (m_sign_policy) {
                // request unknown AA certificate for any received message signed with AT issued by this AA
                m_sign_policy->request_unrecognized_certificate(*aa_digest);
            }
        }
        // TODO: if AA is validated and fails, announce it in cache
    }

    auto public_key = get_public_key(*certificate);
    if (!public_key) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
        return confirm;
    }

    expected<bool> verified = false;
    try {
        ByteBuffer msg_hash = calculate_message_hash(m_crypto, msg.hash_id(),
            msg.signing_payload(), CertificateView { certificate });
        switch (msg.hash_id()) {
            case HashAlgorithm::SHA256:
                verified = verify_message_hash<Sha256Hash>(m_crypto, msg_hash, *signature, *public_key);
                break;
            case HashAlgorithm::SHA384:
                verified = verify_message_hash<Sha384Hash>(m_crypto, msg_hash, *signature, *public_key);
                break;
            default:
                confirm.report = VerificationReport::Incompatible_Protocol;
                return confirm;
        }
    } catch (const std::exception&) {
        // malformed input data, e.g. failing certificate encoding
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }

    // signature failing verification, e.g. by an invalid public key, is no valid signature
    if (!verified.has_value() || !*verified) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    confirm.its_aid = msg.its_aid();
    confirm.permissions = get_app_permissions(*certificate, confirm.its_aid);
    confirm.certificate_id = maybe_digest;
    confirm.report = VerificationReport::Success;

    if (m_cert_cache && confirm.certificate_id) {
        CertificateCache& cache = *m_cert_cache;
        bool already_cached = cache.lookup(*confirm.certificate_id) != nullptr;
        if (!already_cached && confirm.its_aid == aid::CA && m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_sign_policy->request_certificate();
        }

        // update certificate cache with received certificate
        if (contains_certificate(signer_identifier)) {
            cache.store(Certificate { *certificate });
        }
    }

    return confirm;
}

} // namespace v3
} // namespace security
} // namespace vanetza
