#include <vanetza/security/basic_certificate_manager.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{

BasicCertificateManager::BasicCertificateManager(const Clock::time_point& time_now, const Certificate& authorization_ticket, const ecdsa256::KeyPair& authorization_ticket_key, const Certificate& sign_cert) :
    time_now(time_now),
    authorization_ticket(authorization_ticket),
    authorization_ticket_key(authorization_ticket_key),
    sign_cert(sign_cert) { }

const Certificate& BasicCertificateManager::own_certificate()
{
    return authorization_ticket;
}

const ecdsa256::PrivateKey& BasicCertificateManager::own_private_key()
{
    return authorization_ticket_key.private_key;
}

CertificateValidity BasicCertificateManager::check_certificate(const Certificate& certificate)
{
    // ensure at least one time validity constraint is present
    // section 6.7 in TS 103 097 v1.2.1
    bool certificate_has_time_constraint = false;

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

            certificate_has_time_constraint = true;
        }

        // TODO: Support time_start_and_duration and time_end
    }

    // if no time constraint is given, we fail instead of considering it valid
    if (!certificate_has_time_constraint) {
        return CertificateInvalidReason::BROKEN_TIME_PERIOD;
    }

    // check if subject_name is empty
    if (0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::INVALID_NAME;
    }

    // check signer info
    if(get_type(certificate.signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
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
