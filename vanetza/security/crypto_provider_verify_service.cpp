#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/certificate_validator.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/verification.hpp>
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
namespace v2
{

namespace
{

bool assign_permissions(const v2::Certificate& certificate, VerifyConfirm& confirm)
{
    for (auto& subject_attribute : certificate.subject_attributes) {
        if (get_type(subject_attribute) != v2::SubjectAttributeType::ITS_AID_SSP_List) {
            continue;
        }

        auto& permissions = boost::get<std::list<v2::ItsAidSsp> >(subject_attribute);
        for (auto& permission : permissions) {
            if (permission.its_aid == confirm.its_aid) {
                confirm.permissions = permission.service_specific_permissions;
                return true;
            }
        }

        break;
    }

    return false;
}

} // namespace
} // namespace v2

namespace v3
{

namespace
{

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
void handle_p2pcd_requests(CryptoProvider& crypto, const SecuredMessage& msg, SignHeaderPolicy& policy)
{
    const auto& header = msg->content->choice.signedData->tbsData->headerInfo;
    if (header.inlineP2pcdRequest) {
        for (int i = 0; i < header.inlineP2pcdRequest->list.count; ++i) {
            policy.enqueue_p2p_request(create_hashed_id3(*header.inlineP2pcdRequest->list.array[i]));
        }
    }

    if (header.requestedCertificate) {
        const boost::optional<HashedId8> digest = calculate_digest(crypto, *header.requestedCertificate);
        if (digest) {
            policy.discard_p2p_request(truncate(*digest));
        }
    }
}

} // namespace
} // namespace v3

CryptoProviderVerifyService::CryptoProviderVerifyService(const Runtime& runtime, CryptoProvider& crypto,
    PositionProvider& position_provider) :
    m_runtime(runtime), m_crypto(crypto), m_position_provider(position_provider)
{
}

void CryptoProviderVerifyService::use_certificate_cache(v2::CertificateCache* cache)
{
    m_context_v2.m_cert_cache = cache;
}

void CryptoProviderVerifyService::use_certificate_validator(v2::CertificateValidator* validator)
{
    m_context_v2.m_cert_validator = validator;
}

void CryptoProviderVerifyService::use_sign_header_policy(v2::SignHeaderPolicy* policy)
{
    m_context_v2.m_sign_policy = policy;
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

void CryptoProviderVerifyService::use_issuer_lookup(const v3::IssuerLookup* issuers)
{
    m_context_v3.m_issuer_lookup = issuers;
}

VerifyConfirm CryptoProviderVerifyService::verify(const VerifyRequest& request)
{
    struct visitor : public boost::static_visitor<VerifyConfirm>
    {
        explicit visitor(CryptoProviderVerifyService& service) : m_service(service)
        {
        }

        VerifyConfirm operator()(const v2::SecuredMessage& msg) const
        {
            return m_service.verify(msg);
        }

        VerifyConfirm operator()(const v3::SecuredMessage& msg) const
        {
            return m_service.verify(msg);
        }

        CryptoProviderVerifyService& m_service;
    } visitor(*this);

    return boost::apply_visitor(visitor, request.secured_message);
}

VerifyConfirm CryptoProviderVerifyService::verify(const v2::SecuredMessage& secured_message)
{
    // TODO check if certificates in chain have been revoked for all CA certificates, ATs are never revoked
    VerifyConfirm confirm;
    using namespace v2;

    if (PayloadType::Signed != secured_message.payload.type) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (2 != secured_message.protocol_version()) {
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }

    if (!m_context_v2.complete()) {
        confirm.report = VerificationReport::Configuration_Problem;
        return confirm;
    }

    v2::CertificateCache& cert_cache = *m_context_v2.m_cert_cache;
    v2::CertificateValidator& cert_validator = *m_context_v2.m_cert_validator;
    v2::SignHeaderPolicy& sign_policy = *m_context_v2.m_sign_policy;

    // requests for the own certificate or its chain are reported to the sign header policy
    const std::list<HashedId3>* requested_certs = secured_message.header_field<HeaderFieldType::Request_Unrecognized_Certificate>();
    if (requested_certs) {
        for (const HashedId3& requested_cert : *requested_certs) {
            sign_policy.report_certificate_request(requested_cert);
        }
    }

    const IntX* its_aid = secured_message.header_field<HeaderFieldType::Its_Aid>();
    if (!its_aid) {
        // ITS-AID is required to be present, report as incompatible protocol, as that's the closest match
        confirm.report = VerificationReport::Incompatible_Protocol;
        return confirm;
    }
    confirm.its_aid = its_aid->get();

    const SignerInfo* signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
    std::list<v2::Certificate> possible_certificates;
    bool possible_certificates_from_cache = false;

    // use a dummy hash for initialization
    HashedId8 signer_hash;
    signer_hash.fill(0x00);

    if (signer_info) {
        switch (get_type(*signer_info)) {
            case SignerInfoType::Certificate:
                possible_certificates.push_back(boost::get<v2::Certificate>(*signer_info));
                signer_hash = calculate_hash(m_crypto, boost::get<v2::Certificate>(*signer_info));

                if (confirm.its_aid == aid::CA && cert_cache.lookup(signer_hash, SubjectType::Authorization_Ticket).size() == 0) {
                    // Previously unknown certificate, send own certificate in next CAM
                    // See TS 103 097 v1.2.1, section 7.1, 1st bullet, 3rd dash
                    sign_policy.request_certificate();
                }

                break;
            case SignerInfoType::Certificate_Digest_With_SHA256:
                signer_hash = boost::get<HashedId8>(*signer_info);
                possible_certificates.splice(possible_certificates.end(), cert_cache.lookup(signer_hash, SubjectType::Authorization_Ticket));
                possible_certificates_from_cache = true;
                break;
            case SignerInfoType::Certificate_Chain:
            {
                std::list<v2::Certificate> chain = boost::get<std::list<v2::Certificate>>(*signer_info);
                if (chain.size() == 0) {
                    confirm.report = VerificationReport::Signer_Certificate_Not_Found;
                    return confirm;
                } else if (chain.size() > 3) {
                    // prevent DoS by sending very long chains, maximum length is three certificates, because:
                    // AT → AA → Root and no other signatures are allowed, sending the Root is optional
                    confirm.report = VerificationReport::Invalid_Certificate;
                    return confirm;
                }
                // pre-check chain certificates, otherwise they're not available for the ticket check
                for (auto& cert : chain) {
                    // root certificates must already be known, otherwise the validation will fail anyway
                    if (cert.subject_info.subject_type == SubjectType::Authorization_Authority) {
                        // there's no need to report unknown signers at this point, see comment above
                        CertificateValidity validity = cert_validator.check_certificate(cert);

                        // we can abort early if there are invalid AA certificates in the chain
                        if (!validity) {
                            confirm.report = VerificationReport::Invalid_Certificate;
                            confirm.certificate_validity = validity;
                            return confirm;
                        }

                        // We won't cache outdated or premature certificates in the cache and abort early.
                        // This check isn't required as it would just fail below or in the consistency checks,
                        // but it's an optimization and saves us from polluting the cache with such certificates.
                        if (!check_certificate_time(cert, m_runtime.now()) || !check_certificate_region(cert, m_position_provider.position_fix())) {
                            confirm.report = VerificationReport::Invalid_Certificate;
                            return confirm;
                        }

                        cert_cache.insert(cert);
                    }
                }
                // last certificate must be the authorization ticket
                signer_hash = calculate_hash(m_crypto, chain.back());
                possible_certificates.push_back(chain.back());
            }
                break;
            default:
                confirm.report = VerificationReport::Unsupported_Signer_Identifier_Type;
                return confirm;
                break;
        }
    }

    if (possible_certificates.size() == 0) {
        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        confirm.certificate_id = signer_hash;
        sign_policy.request_unrecognized_certificate(signer_hash);
        return confirm;
    }

    if (!check_generation_time(secured_message, m_runtime.now())) {
        confirm.report = VerificationReport::Invalid_Timestamp;
        return confirm;
    }

    // TODO check Duplicate_Message, Invalid_Mobility_Data, Unencrypted_Message, Decryption_Error

    // check signature
    const TrailerField* signature_field = secured_message.trailer_field(TrailerFieldType::Signature);
    const v2::Signature* signature = boost::get<v2::Signature>(signature_field);

    if (!signature) {
        confirm.report = VerificationReport::Unsigned_Message;
        return confirm;
    }

    if (PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256 != get_type(*signature)) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    // check the size of signature.R and siganture.s
    auto ecdsa = extract_ecdsa_signature(*signature);
    const auto field_len = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    if (!ecdsa || ecdsa->s.size() != field_len) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    // verify payload signature with given signature, its r is the x-coordinate of R
    const ByteBuffer payload = convert_for_signing(secured_message, secured_message.trailer_fields);
    const Sha256Hash digest = m_crypto.calculate_sha256_hash(payload.data(), payload.size());
    const security::Signature payload_signature { convert_for_signing(ecdsa->R), ecdsa->s, KeyType::NistP256 };
    boost::optional<v2::Certificate> signer;

    for (const auto& cert : possible_certificates) {
        SubjectType subject_type = cert.subject_info.subject_type;
        if (subject_type != SubjectType::Authorization_Ticket) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Invalid_Signer;
            return confirm;
        }

        const boost::optional<security::PublicKey> public_key = get_verification_key(cert);

        // public key could not be extracted
        if (!public_key) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            return confirm;
        }

        const expected<bool> verified = m_crypto.verify(digest, payload_signature, *public_key);
        if (verified.has_error()) {
            if (verified.error() == SecurityModuleError::InvalidPublicKey) {
                confirm.report = VerificationReport::Invalid_Certificate;
                confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            } else {
                confirm.report = VerificationReport::Configuration_Problem;
            }
            return confirm;
        } else if (*verified) {
            signer = cert;
            break;
        }
    }

    if (!signer) {
        // HashedId8 of authorization tickets is not guaranteed to be globally unique.
        // The collision probability is rather low, but it might happen.
        if (signer_info && get_type(*signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
            // assume a hash collision since we got only a digest with message
            confirm.report = VerificationReport::Signer_Certificate_Not_Found;
        } else {
            // signature does not match the certificate received with this message
            confirm.report = VerificationReport::False_Signature;
        }

        confirm.certificate_id = signer_hash;
        sign_policy.request_unrecognized_certificate(signer_hash);
        return confirm;
    }

    // we can only check the generation location after we have identified the correct certificate
    if (!check_generation_location(secured_message, *signer)) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    CertificateValidity cert_validity = CertificateValidity::valid();
    if (!possible_certificates_from_cache) { // certificates from cache are already verified as trusted
        cert_validity = cert_validator.check_certificate(*signer);
    }

    confirm.certificate_validity = cert_validity;

    // if certificate could not be verified return correct DecapReport
    if (!cert_validity) {
        confirm.report = VerificationReport::Invalid_Certificate;

        if (cert_validity.reason() == CertificateInvalidReason::Unknown_Signer) {
            if (get_type(signer->signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
                auto signer_hash = boost::get<HashedId8>(signer->signer_info);
                confirm.certificate_id = signer_hash;
                sign_policy.request_unrecognized_certificate(signer_hash);
            }
        }

        return confirm;
    }

    if (!check_certificate_time(*signer, m_runtime.now())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Time_Period;
        return confirm;
    }

    if (!check_certificate_region(*signer, m_position_provider.position_fix())) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Off_Region;
        return confirm;
    }

    // Assign permissions from the certificate based on the message AID already present in the confirm
    // and reject the certificate if no permissions are present for the claimed AID.
    if (!assign_permissions(*signer, confirm)) {
        // This might seem weird, because the certificate itself is valid, but not for the received message.
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Insufficient_ITS_AID;
        return confirm;
    }

    // cache only certificates that are useful, one that mismatches its restrictions isn't
    cert_cache.insert(*signer);

    confirm.report = VerificationReport::Success;
    return confirm;
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
    auto maybe_digest = get_certificate_id(m_crypto, signer_identifier);
    if (m_context_v3.m_cert_cache && maybe_digest) {
        bool was_unknown_station = m_context_v3.m_cert_cache->announce(*maybe_digest);
        if (was_unknown_station && msg.its_aid() == aid::CA && m_context_v3.m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_context_v3.m_sign_policy->request_certificate();
        }
    }

    if (msg.its_aid() == aid::CA && m_context_v3.m_sign_policy) {
        handle_p2pcd_requests(m_crypto, msg, *m_context_v3.m_sign_policy);
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

    if (m_context_v3.m_issuer_lookup) {
        const Certificate* issuer = find_trusted_issuer(*m_context_v3.m_issuer_lookup, *certificate, confirm);
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
