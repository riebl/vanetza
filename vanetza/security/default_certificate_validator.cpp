#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/trust_store.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{

DefaultCertificateValidator::DefaultCertificateValidator(const Clock::time_point& time_now, const TrustStore& trust_store, CertificateCache& cert_cache) :
    m_crypto_backend(create_backend("default")),
    m_time_now(time_now),
    m_trust_store(trust_store),
    m_cert_cache(cert_cache)
{
}

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
                return CertificateValidity(CertificateInvalidReason::BROKEN_TIME_PERIOD, certificate);
            }

            // check if certificate is premature or outdated
            auto now = convert_time32(m_time_now);
            if (now < start_and_end.start_validity || now > start_and_end.end_validity) {
                return CertificateValidity(CertificateInvalidReason::OFF_TIME_PERIOD, certificate);
            }

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_End) {
            EndValidity end = boost::get<EndValidity>(validity_restriction);

            // check if certificate is outdated
            auto now = convert_time32(m_time_now);
            if (now > end) {
                return CertificateValidity(CertificateInvalidReason::OFF_TIME_PERIOD, certificate);
            }

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_Start_And_Duration) {
            StartAndDurationValidity start_and_duration = boost::get<StartAndDurationValidity>(validity_restriction);

            // check if certificate is premature or outdated
            auto now = convert_time32(m_time_now);
            std::chrono::seconds duration = start_and_duration.duration.to_seconds();
            auto end = start_and_duration.start_validity + duration.count();
            if (now < start_and_duration.start_validity || now > end) {
                return CertificateValidity(CertificateInvalidReason::OFF_TIME_PERIOD, certificate);
            }

            ++certificate_time_constraints;
        }
    }

    // if not exactly one time constraint is given, we fail instead of considering it valid
    if (1 != certificate_time_constraints) {
        return CertificateValidity(CertificateInvalidReason::BROKEN_TIME_PERIOD, certificate);
    }

    SubjectType subject_type = certificate.subject_info.subject_type;

    // check if subject_name is empty if certificate is authorization ticket
    if (subject_type == SubjectType::Authorization_Ticket && 0 != certificate.subject_info.subject_name.size()) {
        return CertificateValidity(CertificateInvalidReason::INVALID_NAME, certificate);
    }

    // check signer info
    if (get_type(certificate.signer_info) != SignerInfoType::Certificate_Digest_With_SHA256) {
        return CertificateValidity(CertificateInvalidReason::INVALID_SIGNER, certificate);
    }

    HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.signature);
    if (!sig) {
        return CertificateValidity(CertificateInvalidReason::MISSING_SIGNATURE, certificate);
    }

    // create buffer of certificate
    ByteBuffer cert = convert_for_signing(certificate);

    std::list<Certificate> possible_signers = m_trust_store.lookup(signer_hash);

    for (auto& possible_signer : possible_signers) {
        auto verification_key = get_public_key(possible_signer);

        // this should never happen, as the verify service already ensures a key is present
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend->verify_data(verification_key.get(), cert, sig.get())) {
            return CertificateValidity::valid();
        }
    }

    possible_signers = m_cert_cache.lookup(signer_hash);

    for (auto& possible_signer : possible_signers) {
        auto verification_key = get_public_key(possible_signer);

        // this should never happen, as the verify service already ensures a key is present
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend->verify_data(verification_key.get(), cert, sig.get())) {
            // TODO: Add max depth limitation
            CertificateValidity validity = check_certificate(possible_signer);

            if (validity) {
                m_cert_cache.put(possible_signer);
            }

            return validity;
        }
    }

    return CertificateValidity(CertificateInvalidReason::UNKNOWN_SIGNER, certificate);
}

} // namespace security
} // namespace vanetza
