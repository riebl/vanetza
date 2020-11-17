#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/certificate_validator.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <boost/optional.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{
namespace
{

bool check_generation_time(const SecuredMessageV2& message, Clock::time_point now)
{
    using namespace std::chrono;

    bool valid = false;
    const Time64* generation_time = message.header_field<HeaderFieldType::Generation_Time>();
    if (generation_time) {
        // Values are picked from C2C-CC Basic System Profile v1.1.0, see RS_BSP_168
        static const auto generation_time_future = milliseconds(40);
        static const Clock::duration generation_time_past_default = minutes(10);
        static const Clock::duration generation_time_past_ca = seconds(2);
        auto generation_time_past = generation_time_past_default;

        const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
        if (its_aid && aid::CA == *its_aid) {
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

bool check_generation_location(const SecuredMessageV2& message, const Certificate& cert)
{
    const IntX* its_aid = message.header_field<HeaderFieldType::Its_Aid>();
    if (its_aid && aid::CA == *its_aid) {
        return true; // no check required for CAMs, field not even allowed
    }

    const ThreeDLocation* generation_location = message.header_field<HeaderFieldType::Generation_Location>();
    if (generation_location) {
        auto region = cert.get_restriction<ValidityRestrictionType::Region>();

        if (!region || get_type(*region) == RegionType::None) {
            return true;
        }

        return is_within(TwoDLocation(*generation_location), *region);
    }

    return false;
}

bool check_certificate_time(const Certificate& certificate, Clock::time_point now)
{
    auto time = certificate.get_restriction<ValidityRestrictionType::Time_Start_And_End>();
    auto time_now = convert_time32(now);

    if (!time) {
        return false; // must be present
    }

    if (time->start_validity > time_now || time->end_validity < time_now) {
        return false; // premature or outdated
    }

    return true;
}

bool check_certificate_region(const Certificate& certificate, const PositionFix& position)
{
    auto region = certificate.get_restriction<ValidityRestrictionType::Region>();

    if (!region || get_type(*region) == RegionType::None) {
        return true;
    }

    if (!position.confidence) {
        return false; // cannot check region restrictions without good position fix
    }

    return is_within(TwoDLocation(position.latitude, position.longitude), *region);
}

bool assign_permissions(const Certificate& certificate, VerifyConfirm& confirm)
{
    for (auto& subject_attribute : certificate.subject_attributes) {
        if (get_type(subject_attribute) != SubjectAttributeType::ITS_AID_SSP_List) {
            continue;
        }

        auto& permissions = boost::get<std::list<ItsAidSsp> >(subject_attribute);
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

VerifyService straight_verify_service(const Runtime& rt, CertificateProvider& cert_provider, CertificateValidator& certs, Backend& backend, CertificateCache& cert_cache, SignHeaderPolicy& sign_policy, PositionProvider& positioning)
{
    return [&](VerifyRequest&& request) -> VerifyConfirm {
        // TODO check if certificates in chain have been revoked for all CA certificates, ATs are never revoked

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
        std::list<Certificate> possible_certificates;
        bool possible_certificates_from_cache = false;

        // use a dummy hash for initialization
        HashedId8 signer_hash;
        signer_hash.fill(0x00);

        if (signer_info) {
            switch (get_type(*signer_info)) {
                case SignerInfoType::Certificate:
                    possible_certificates.push_back(boost::get<Certificate>(*signer_info));
                    signer_hash = calculate_hash(boost::get<Certificate>(*signer_info));

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
                    std::list<Certificate> chain = boost::get<std::list<Certificate>>(*signer_info);
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
                            CertificateValidity validity = certs.check_certificate(cert);

                            // we can abort early if there are invalid AA certificates in the chain
                            if (!validity) {
                                confirm.report = VerificationReport::Invalid_Certificate;
                                confirm.certificate_validity = validity;
                                return confirm;
                            }

                            // We won't cache outdated or premature certificates in the cache and abort early.
                            // This check isn't required as it would just fail below or in the consistency checks,
                            // but it's an optimization and saves us from polluting the cache with such certificates.
                            if (!check_certificate_time(cert, rt.now()) || !check_certificate_region(cert, positioning.position_fix())) {
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

        if (!check_generation_time(secured_message, rt.now())) {
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
        boost::optional<Certificate> signer;

        for (const auto& cert : possible_certificates) {
            SubjectType subject_type = cert.subject_info.subject_type;
            if (subject_type != SubjectType::Authorization_Ticket) {
                confirm.report = VerificationReport::Invalid_Certificate;
                confirm.certificate_validity = CertificateInvalidReason::Invalid_Signer;
                return confirm;
            }

            boost::optional<ecdsa256::PublicKey> public_key = get_public_key(cert, backend);

            // public key could not be extracted
            if (!public_key) {
                confirm.report = VerificationReport::Invalid_Certificate;
                confirm.certificate_validity = CertificateInvalidReason::Missing_Public_Key;
                return confirm;
            }

            if (backend.verify_data(public_key.get(), payload, *ecdsa)) {
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
            cert_validity = certs.check_certificate(*signer);
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

        if (!check_certificate_time(*signer, rt.now())) {
            confirm.report = VerificationReport::Invalid_Certificate;
            confirm.certificate_validity = CertificateInvalidReason::Off_Time_Period;
            return confirm;
        }

        if (!check_certificate_region(*signer, positioning.position_fix())) {
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
    };
}

VerifyService dummy_verify_service(VerificationReport report, CertificateValidity validity)
{
    return [=](VerifyRequest&& request) -> VerifyConfirm {
        VerifyConfirm confirm;
        confirm.report = report;
        confirm.certificate_validity = validity;
        const IntX* its_aid = request.secured_message.header_field<HeaderFieldType::Its_Aid>();
        confirm.its_aid = its_aid ? its_aid->get() : 0;
        return confirm;
    };
}

} // namespace security
} // namespace vanetza
