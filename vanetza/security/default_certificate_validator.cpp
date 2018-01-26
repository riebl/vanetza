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
namespace
{

bool extract_validity_time(const Certificate& certificate, boost::optional<Time32>& start, boost::optional<Time32>& end)
{
    unsigned certificate_time_constraints = 0;

    for (auto& restriction : certificate.validity_restriction) {
        ValidityRestriction validity_restriction = restriction;
        ValidityRestrictionType type = get_type(validity_restriction);

        if (type == ValidityRestrictionType::Time_Start_And_End) {
            // change start and end time of certificate validity
            StartAndEndValidity start_and_end = boost::get<StartAndEndValidity>(validity_restriction);

            // check if certificate validity restriction timestamps are logically correct
            if (start_and_end.start_validity >= start_and_end.end_validity) {
                return false;
            }

            start = start_and_end.start_validity;
            end = start_and_end.end_validity;

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_End) {
            EndValidity time_end = boost::get<EndValidity>(validity_restriction);
            end = time_end;

            ++certificate_time_constraints;
        } else if (type == ValidityRestrictionType::Time_Start_And_Duration) {
            StartAndDurationValidity start_and_duration = boost::get<StartAndDurationValidity>(validity_restriction);

            start = start_and_duration.start_validity;
            end = start_and_duration.start_validity + start_and_duration.duration.to_seconds().count();

            ++certificate_time_constraints;
        }
    }

    return certificate_time_constraints == 1;
}

bool check_time_consistent(const Certificate& certificate, const Certificate& signer)
{
    boost::optional<Time32> certificate_time_start;
    boost::optional<Time32> certificate_time_end;

    boost::optional<Time32> signer_time_start;
    boost::optional<Time32> signer_time_end;

    if (!extract_validity_time(certificate, certificate_time_start, certificate_time_end)) {
        return false;
    }

    if (!extract_validity_time(signer, signer_time_start, signer_time_end)) {
        return false;
    }

    if (signer_time_start && *signer_time_start > *certificate_time_start) {
        return false;
    }

    if (signer_time_end && *signer_time_end < *certificate_time_end) {
        return false;
    }

    return true;
}

} // namespace

DefaultCertificateValidator::DefaultCertificateValidator(Backend& backend, const Clock::time_point& time_now,
        const TrustStore& trust_store, CertificateCache& cert_cache) :
    m_crypto_backend(backend),
    m_time_now(time_now),
    m_trust_store(trust_store),
    m_cert_cache(cert_cache)
{
}

CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate)
{
    return check_certificate(certificate, 10);
}

CertificateValidity DefaultCertificateValidator::check_certificate(const Certificate& certificate, uint8_t max_depth)
{
    if (max_depth == 0) {
        return CertificateInvalidReason::TOO_LONG_CHAIN;
    }

    boost::optional<Time32> certificate_time_start;
    boost::optional<Time32> certificate_time_end;

    // ensure exactly one time validity constraint is present
    // section 6.7 in TS 103 097 v1.2.1
    if (!extract_validity_time(certificate, certificate_time_start, certificate_time_end)) {
        return CertificateInvalidReason::BROKEN_TIME_PERIOD;
    }

    // check if certificate is premature or outdated
    auto now = convert_time32(m_time_now);
    if (certificate_time_start && certificate_time_end) {
        if (*certificate_time_start >= certificate_time_end) {
            return CertificateInvalidReason::BROKEN_TIME_PERIOD;
        }
    }

    if (certificate_time_start && now < *certificate_time_start) {
        return CertificateInvalidReason::OFF_TIME_PERIOD;
    }

    if (certificate_time_end && now > *certificate_time_end) {
        return CertificateInvalidReason::OFF_TIME_PERIOD;
    }

    SubjectType subject_type = certificate.subject_info.subject_type;

    // check if subject_name is empty if certificate is authorization ticket
    if (subject_type == SubjectType::Authorization_Ticket && 0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::INVALID_NAME;
    }

    // check signer info
    if (get_type(certificate.signer_info) != SignerInfoType::Certificate_Digest_With_SHA256) {
        return CertificateInvalidReason::INVALID_SIGNER;
    }

    HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);

    // try to extract ECDSA signature
    boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(certificate.signature);
    if (!sig) {
        return CertificateInvalidReason::MISSING_SIGNATURE;
    }

    // create buffer of certificate
    ByteBuffer cert = convert_for_signing(certificate);

    const std::list<Certificate> possible_trusted_signers = m_trust_store.lookup(signer_hash);
    for (auto& possible_signer : possible_trusted_signers) {
        auto verification_key = get_public_key(possible_signer);
        // this should never happen, as the verify service already ensures a key is present
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend.verify_data(verification_key.get(), cert, sig.get())) {
            if (!check_time_consistent(certificate, possible_signer)) {
                return CertificateInvalidReason::BROKEN_TIME_PERIOD;
            }

            return CertificateValidity::valid();
        }
    }

    const std::list<Certificate> possible_signers = m_cert_cache.lookup(signer_hash);
    for (auto& possible_signer : possible_signers) {
        auto verification_key = get_public_key(possible_signer);
        // this should never happen, as the verify service already ensures a key is present
        if (!verification_key) {
            continue;
        }

        if (m_crypto_backend.verify_data(verification_key.get(), cert, sig.get())) {
            if (!check_time_consistent(certificate, possible_signer)) {
                return CertificateInvalidReason::BROKEN_TIME_PERIOD;
            }

            CertificateValidity validity = check_certificate(possible_signer, max_depth - 1);

            if (validity) {
                // Renews certificate in cache
                m_cert_cache.insert(possible_signer);
            }

            return validity;
        }
    }

    return CertificateInvalidReason::UNKNOWN_SIGNER;
}

} // namespace security
} // namespace vanetza
