#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/straight_verify_service.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/certificate_validator.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/verification.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <boost/optional.hpp>

// asn1c quirk
struct Vanetza_Security_Certificate : public Vanetza_Security_CertificateBase {};

namespace vanetza
{
namespace security
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


StraightVerifyService::StraightVerifyService(const Runtime& runtime, Backend& backend, PositionProvider& position) :
    m_runtime(runtime), m_backend(backend),m_position_provider(position)
{
}

void StraightVerifyService::use_certificate_cache(v2::CertificateCache* cache)
{
    m_context_v2.m_cert_cache = cache;
}

void StraightVerifyService::use_certificate_provider(v2::CertificateProvider* provider)
{
    m_context_v2.m_cert_provider = provider;
}

void StraightVerifyService::use_certificate_validator(v2::CertificateValidator* validator)
{
    m_context_v2.m_cert_validator = validator;
}

void StraightVerifyService::use_sign_header_policy(v2::SignHeaderPolicy* policy)
{
    m_context_v2.m_sign_policy = policy;
}

void StraightVerifyService::use_certificate_provider(v3::CertificateProvider* provider)
{
    m_context_v3.m_cert_provider = provider;
}

void StraightVerifyService::use_certificate_validator(v3::CertificateValidator* validator)
{
    m_context_v3.m_cert_validator = validator;
}

void StraightVerifyService::use_sign_header_policy(v3::SignHeaderPolicy* policy)
{
    m_context_v3.m_sign_policy = policy;
}

VerifyConfirm StraightVerifyService::verify(const VerifyRequest& request)
{
    struct visitor : public boost::static_visitor<VerifyConfirm>
    {
        visitor(StraightVerifyService* service) : m_service(service)
        {
        }

        VerifyConfirm operator()(const v2::SecuredMessage& msg)
        {
            return m_service->verify(msg);
        }

        VerifyConfirm operator()(const v3::SecuredMessage& msg)
        {
            return m_service->verify(msg);
        }

        StraightVerifyService* m_service = nullptr;
    } visitor(this);

    return boost::apply_visitor(visitor, request.secured_message);
}

VerifyConfirm StraightVerifyService::verify(const v2::SecuredMessage& secured_message)
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

    v2::CertificateProvider& cert_provider = *m_context_v2.m_cert_provider;
    v2::CertificateCache& cert_cache = *m_context_v2.m_cert_cache;
    v2::CertificateValidator& cert_validator = *m_context_v2.m_cert_validator;
    v2::SignHeaderPolicy& sign_policy = *m_context_v2.m_sign_policy;

    const std::list<HashedId3>* requested_certs = secured_message.header_field<HeaderFieldType::Request_Unrecognized_Certificate>();
    if (requested_certs) {
        for (auto& requested_cert : *requested_certs) {
            if (truncate(calculate_hash(cert_provider.own_certificate())) == requested_cert) {
                sign_policy.request_certificate();
            }

            for (auto& cert : cert_provider.own_chain()) {
                if (truncate(calculate_hash(cert)) == requested_cert) {
                    sign_policy.request_certificate_chain();
                }
            }
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
                signer_hash = calculate_hash(boost::get<v2::Certificate>(*signer_info));

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
                signer_hash = calculate_hash(chain.back());
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

    // verify payload signature with given signature
    ByteBuffer payload = convert_for_signing(secured_message, secured_message.trailer_fields);
    boost::optional<v2::Certificate> signer;

    for (const auto& cert : possible_certificates) {
        SubjectType subject_type = cert.subject_info.subject_type;
        if (subject_type != SubjectType::Authorization_Ticket) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Invalid_Signer;
            return confirm;
        }

        boost::optional<ecdsa256::PublicKey> public_key = get_public_key(cert, m_backend);

        // public key could not be extracted
        if (!public_key) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
            return confirm;
        }

        if (m_backend.verify_data(public_key.get(), payload, *ecdsa)) {
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

VerifyConfirm StraightVerifyService::verify(const v3::SecuredMessage& msg)
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

    struct certificate_lookup_visitor : public boost::static_visitor<const v3::asn1::Certificate*> {
        certificate_lookup_visitor(v3::CertificateProvider* provider) :
            m_cache(provider != nullptr ? &provider->cache() : nullptr)
        {
        }

        const v3::asn1::Certificate* operator()(const v3::asn1::HashedId8* digest)
        {
            // look up certificate matching digest in local storage
            if (m_cache && digest) {
                const v3::Certificate* found = m_cache->lookup(v3::convert(*digest));
                return found ? found->content() : nullptr;
            } else {
                return nullptr;
            }
        }

        const v3::asn1::Certificate* operator()(const v3::asn1::Certificate* cert)
        {
            return cert;
        }

        v3::CertificateCache* m_cache;
    } certificate_lookup_visitor(m_context_v3.m_cert_provider);
    auto signer_identifier = msg.signer_identifier();

    // track "known" stations
    auto maybe_digest = v3::get_certificate_id(signer_identifier);
    if (m_context_v3.m_cert_provider && maybe_digest) {
        bool was_unknown_station = m_context_v3.m_cert_provider->cache().announce(*maybe_digest);
        if (was_unknown_station && msg.its_aid() == aid::CA && m_context_v3.m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_context_v3.m_sign_policy->request_certificate();
        }
    }

    // check if a ITS-AID 36 (CAM) with inline cert request shall be handled by us
    if (msg.its_aid() == aid::CA && m_context_v3.m_sign_policy && m_context_v3.m_cert_provider) {
        Vanetza_Security_SequenceOfHashedId3* requests = msg->content->choice.signedData->tbsData->headerInfo.inlineP2pcdRequest;
        if (requests) {
            for (int i = 0; i < requests->list.count; ++i)
            {
                const Vanetza_Security_HashedId3_t* req_digest = requests->list.array[i];
                const HashedId3 hid3 = create_hashed_id3(*req_digest);
                m_context_v3.m_sign_policy->enqueue_p2p_request(hid3);
            }
        }

        Vanetza_Security_Certificate* included_cert = msg->content->choice.signedData->tbsData->headerInfo.requestedCertificate;
        if (included_cert) {
            auto maybe_digest = v3::calculate_digest(*included_cert);
            if (maybe_digest) {
                m_context_v3.m_sign_policy->discard_p2p_request(truncate(*maybe_digest));
            }
        }
    }

    const v3::asn1::Certificate* certificate = boost::apply_visitor(certificate_lookup_visitor, signer_identifier);
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
        auto verdict = m_context_v3.m_cert_validator->valid_for_signing(v3::CertificateView { certificate }, msg.its_aid());
        if (verdict != v3::CertificateValidator::Verdict::Valid) {
            confirm.report = VerificationReport::Invalid_Certificate;
            return confirm;
        }
    }

    boost::optional<HashedId8> aa_digest;
    switch (certificate->issuer.present)
    {
        case Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest:
            aa_digest = v3::convert(certificate->issuer.choice.sha256AndDigest);
            break;
        case Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest:
            aa_digest = v3::convert(certificate->issuer.choice.sha384AndDigest);
            break;
        default:
            break;
    }

    if (aa_digest && m_context_v3.m_cert_provider) {
        if (!m_context_v3.m_cert_provider->cache().is_known(*aa_digest)) {
            if (m_context_v3.m_sign_policy) {
                // request unknown AA certificate for any received message signed with AT issued by this AA
                m_context_v3.m_sign_policy->request_unrecognized_certificate(*aa_digest);
            }
        }
        // TODO: if AA is validated and fails, announce it in cache
    }

    auto public_key = v3::get_public_key(*certificate);
    if (!public_key) {
        confirm.report = VerificationReport::Invalid_Certificate;
        confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
        return confirm;
    }

    ByteBuffer msg_hash = v3::calculate_message_hash(m_backend, msg.hash_id(),
        msg.signing_payload(), v3::CertificateView { certificate });
    if (!m_backend.verify_digest(*public_key, msg_hash, *signature)) {
        confirm.report = VerificationReport::False_Signature;
        return confirm;
    }

    confirm.its_aid = msg.its_aid();
    confirm.permissions = v3::get_app_permissions(*certificate, confirm.its_aid);
    confirm.certificate_id = maybe_digest;
    confirm.report = VerificationReport::Success;

    if (m_context_v3.m_cert_provider && confirm.certificate_id) {
        v3::CertificateCache& cache = m_context_v3.m_cert_provider->cache();
        bool already_cached = cache.lookup(*confirm.certificate_id) != nullptr;
        if (!already_cached && confirm.its_aid == aid::CA && m_context_v3.m_sign_policy) {
            // CAM from unknown station received, add our certificate to next outgoing message
            m_context_v3.m_sign_policy->request_certificate();
        }

        // update certificate cache with received certificate
        if (v3::contains_certificate(signer_identifier)) {
            cache.store(v3::Certificate { *certificate });
        }
    }

    return confirm;
}

} // namespace security
} // namespace vanetza
