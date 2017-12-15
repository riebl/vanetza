#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/certificate_validator.hpp>
#include <vanetza/security/its_aid.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <boost/optional.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace
{

bool check_generation_time(Clock::time_point now, const SecuredMessageV2& message)
{
    using namespace std::chrono;

    bool valid = false;
    const HeaderField* generation_time_field = message.header_field(HeaderFieldType::Generation_Time);
    const Time64* generation_time = boost::get<Time64>(generation_time_field);
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const HeaderField* its_aid_field = message.header_field(HeaderFieldType::Its_Aid);
        const IntX* its_aid = boost::get<IntX>(its_aid_field);
        if (its_aid && itsAidCa == *its_aid) {
            generation_time_past = generation_time_past_ca;
        }

        if (*generation_time > convert_time64(now + generation_time_future)) {
            valid = false;
        } else if (*generation_time < convert_time64(now - generation_time_past)) {
            valid = false;
        } else {
            valid = true;
        }
    }

    return valid;
}

} // namespace

VerifyService straight_verify_service(Runtime& rt, CertificateProvider& cert_provider, CertificateValidator& certs, Backend& backend, CertificateCache& cert_cache, SignHeaderPolicy& sign_policy)
{
    return [&](VerifyRequest&& request) -> VerifyConfirm {
        VerifyConfirm confirm;
        const SecuredMessage& secured_message = request.secured_message;

        if (PayloadType::Signed != secured_message.payload.type) {
            confirm.report = VerificationReport::Unsigned_Message;
            return confirm;
        }

        if (2 != secured_message.protocol_version()) {
            confirm.report = VerificationReport::Incompatible_Protocol;
            return confirm;
        }

        const std::list<HashedId3>* requested_certs = secured_message.header_field<HeaderFieldType::Request_Unrecognized_Certificate>();
        if (requested_certs) {
            for (auto& requested_cert : *requested_certs) {
                if (truncate(calculate_hash(cert_provider.own_certificate())) == requested_cert) {
                    sign_policy.report_requested_certificate();
                }

                for (auto& cert : cert_provider.own_chain()) {
                    if (truncate(calculate_hash(cert)) == requested_cert) {
                        sign_policy.report_requested_certificate_chain();
                    }
                }
            }
        }

        const IntX* its_aid = secured_message.header_field<HeaderFieldType::Its_Aid>();
        confirm.its_aid = its_aid ? *its_aid : IntX(0);

        const SignerInfo* signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        std::list<Certificate> possible_certificates;

        // use a dummy hash for initialization
        HashedId8 signer_hash = HashedId8({ 0, 0, 0, 0, 0, 0, 0, 0 });

        if (signer_info) {
            switch (get_type(*signer_info)) {
                case SignerInfoType::Certificate:
                    possible_certificates.push_back(boost::get<Certificate>(*signer_info));
                    signer_hash = calculate_hash(boost::get<Certificate>(*signer_info));
                    break;
                case SignerInfoType::Certificate_Digest_With_SHA256:
                    signer_hash = boost::get<HashedId8>(*signer_info);
                    possible_certificates.splice(possible_certificates.end(), cert_cache.lookup(signer_hash));
                    break;
                case SignerInfoType::Self:
                case SignerInfoType::Certificate_Digest_With_Other_Algorithm:
                    break;
                case SignerInfoType::Certificate_Chain:
                {
                    std::list<Certificate> chain = boost::get<std::list<Certificate>>(*signer_info);
                    if (chain.size() == 0) {
                        confirm.report = VerificationReport::Signer_Certificate_Not_Found;
                        return confirm;
                    }
                    // pre-check chain certificates in reverse order, otherwise they're not available for the ticket check
                    for (auto& cert : boost::adaptors::reverse(chain)) {
                        if (cert.subject_info.subject_type == SubjectType::Authorization_Authority) {
                            CertificateValidity validity = certs.check_certificate(cert);
                            if (validity) {
                                cert_cache.put(cert);
                            }
                        }
                    }
                    signer_hash = calculate_hash(chain.front());
                    possible_certificates.push_back(chain.front());
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
            sign_policy.report_unknown_certificate(signer_hash);
            return confirm;
        }

        if (!check_generation_time(rt.now(), secured_message)) {
            confirm.report = VerificationReport::Invalid_Timestamp;
            return confirm;
        }

        // TODO check Duplicate_Message, Invalid_Mobility_Data, Unencrypted_Message, Decryption_Error

        // check signature
        const TrailerField* signature_field = secured_message.trailer_field(TrailerFieldType::Signature);
        const Signature* signature = boost::get<Signature>(signature_field);

        if (!signature) {
            confirm.report = VerificationReport::Unsigned_Message;
            return confirm;
        }

        if (PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256 != get_type(*signature)) {
            confirm.report = VerificationReport::False_Signature;
            return confirm;
        }

        // check the size of signature.R and siganture.s
        auto ecdsa = extract_ecdsa_signature(*signature);
        const auto field_len = field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
        if (!ecdsa || ecdsa->s.size() != field_len) {
            confirm.report = VerificationReport::False_Signature;
            return confirm;
        }

        // verify payload signature with given signature
        ByteBuffer payload = convert_for_signing(secured_message, get_size(*signature_field));
        boost::optional<Certificate> signer;

        for (auto& cert : possible_certificates) {
            boost::optional<ecdsa256::PublicKey> public_key = get_public_key(cert);

            // public key could not be extracted
            if (!public_key) {
                confirm.report = VerificationReport::Invalid_Certificate;
                return confirm;
            }

            if (backend.verify_data(public_key.get(), payload, *ecdsa)) {
                signer = cert;
                break;
            }
        }

        if (!signer) {
            // could be a colliding HashedId8, but the probability is pretty low
            confirm.report = VerificationReport::Signer_Certificate_Not_Found;
            confirm.certificate_id = signer_hash;
            sign_policy.report_unknown_certificate(signer_hash);
            return confirm;
        }

        // TODO check if Certificate_Chain is inconsistant
        CertificateValidity cert_validity = certs.check_certificate(signer.get());

        // if certificate could not be verified return correct DecapReport
        if (!cert_validity) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = cert_validity;

            if (cert_validity.reason() == CertificateInvalidReason::UNKNOWN_SIGNER) {
                const Certificate& invalid_cert = cert_validity.invalid_certificate();

                if (get_type(invalid_cert.signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
                    HashedId8 signer_hash = boost::get<HashedId8>(invalid_cert.signer_info);

                    confirm.certificate_id = signer_hash;
                    sign_policy.report_unknown_certificate(*confirm.certificate_id);
                }
            }

            return confirm;
        }

        // TODO check if Revoked_Certificate

        cert_cache.put(signer.get());

        confirm.report = VerificationReport::Success;

        return confirm;
    };
}

VerifyService dummy_verify_service(VerificationReport report, CertificateValidity validity)
{
    return [=](VerifyRequest&& request) -> VerifyConfirm {
        VerifyConfirm confirm;
        confirm.report = report;
        confirm.certificate_validity = validity;
        const IntX* its_aid = request.secured_message.header_field<HeaderFieldType::Its_Aid>();
        confirm.its_aid = its_aid ? *its_aid : IntX(0);
        return confirm;
    };
}

} // namespace security
} // namespace vanetza
