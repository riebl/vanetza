#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{

DefaultCertificateValidator::DefaultCertificateValidator(const Clock::time_point& time_now, const Certificate& sign_cert) :
    time_now(time_now),
    sign_cert(sign_cert) { }

CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate)
{
    // ensure exactly one time validity constraint is present
    // section 6.7 in TS 103 097 v1.2.1
    unsigned certificate_time_constraints = 0;

    // check validity restriction
    for (auto& restriction : certificate.validity_restriction) {
        ValidityRestriction validity_restriction = restriction;
        ValidityRestrictionType type = get_type(validity_restriction);

        if (type == ValidityRestrictionType::Time_Start_And_End) {
            // change start and end time of certificate validity
            StartAndEndValidity start_and_end = boost::get<StartAndEndValidity>(validity_restriction);

            // check if certificate validity restriction timestamps are logically correct
            if (start_and_end.start_validity >= start_and_end.end_validity) {
                return CertificateInvalidReason::BROKEN_TIME_PERIOD;
            }

            // check if certificate is premature or outdated
            auto now = convert_time32(time_now);
            if (now < start_and_end.start_validity || now > start_and_end.end_validity) {
                return CertificateInvalidReason::OFF_TIME_PERIOD;
            }

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_End) {
            EndValidity end = boost::get<EndValidity>(validity_restriction);

            // check if certificate is outdated
            auto now = convert_time32(time_now);
            if (now > end) {
                return CertificateInvalidReason::OFF_TIME_PERIOD;
            }

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_Start_And_Duration) {
            StartAndDurationValidity start_and_duration = boost::get<StartAndDurationValidity>(validity_restriction);

            // check if certificate is premature or outdated
            auto now = convert_time32(time_now);
            std::chrono::seconds duration = start_and_duration.duration.to_seconds();
            auto end = start_and_duration.start_validity + duration.count();
            if (now < start_and_duration.start_validity || now > end) {
                return CertificateInvalidReason::OFF_TIME_PERIOD;
            }

            ++certificate_time_constraints;
        }
    }

    // if not exactly one time constraint is given, we fail instead of considering it valid
    if (1 != certificate_time_constraints) {
        return CertificateInvalidReason::BROKEN_TIME_PERIOD;
    }

    // check if subject_name is empty
    if (0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::INVALID_NAME;
    }

    // check signer info
    if (get_type(certificate.signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
        HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);
        if(signer_hash != calculate_hash(sign_cert)) {
            return CertificateInvalidReason::INVALID_ROOT_HASH;
        }
    }

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.signature);
    if (!sig) {
        return CertificateInvalidReason::MISSING_SIGNATURE;
    }

    // create buffer of certificate
    ByteBuffer cert = convert_for_signing(certificate);
    auto verification_key = get_public_key(sign_cert);

    // this should never happen, as the verify service already ensures a key is present
    if (!verification_key) {
        return CertificateInvalidReason::INVALID_SIGNATURE;
    }

    if (!crypto_backend.verify_data(verification_key.get(), cert, sig.get())) {
        return CertificateInvalidReason::INVALID_SIGNATURE;
    }

    return CertificateValidity::valid();
}

} // namespace security
} // namespace vanetza
