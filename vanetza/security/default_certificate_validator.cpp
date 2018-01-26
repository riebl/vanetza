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
            start = boost::none;
            end = boost::get<EndValidity>(validity_restriction);

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

bool check_time_consistency(const Certificate& certificate, const Certificate& signer)
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

    if (signer_time_start) {
        if (!certificate_time_start) {
            return false;
        }

        if (*signer_time_start > *certificate_time_start) {
            return false;
        }
    }

    if (signer_time_end) {
        if (!certificate_time_end) {
            return false;
        }

        if (*signer_time_end < *certificate_time_end) {
            return false;
        }
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
    unsigned depth = 0;
    bool in_trust_store = false;

    Time32 now = convert_time32(m_time_now);
    Certificate current_cert = certificate;

    while (++depth < 10) {
        boost::optional<Time32> cert_time_start;
        boost::optional<Time32> cert_time_end;

        // ensure exactly one time validity constraint is present
        // section 6.7 in TS 103 097 v1.2.1
        if (!extract_validity_time(current_cert, cert_time_start, cert_time_end)) {
            return CertificateInvalidReason::BROKEN_TIME_PERIOD;
        }

        // check if certificate is premature or outdated
        if (cert_time_start && cert_time_end) {
            if (*cert_time_start >= *cert_time_end) {
                return CertificateInvalidReason::BROKEN_TIME_PERIOD;
            }
        }

        if (cert_time_start && now < *cert_time_start) {
            return CertificateInvalidReason::OFF_TIME_PERIOD;
        }

        if (cert_time_end && now > *cert_time_end) {
            return CertificateInvalidReason::OFF_TIME_PERIOD;
        }

        SubjectType subject_type = current_cert.subject_info.subject_type;

        // check if subject_name is empty if certificate is authorization ticket
        if (subject_type == SubjectType::Authorization_Ticket && 0 != current_cert.subject_info.subject_name.size()) {
            return CertificateInvalidReason::INVALID_NAME;
        }

        // check signer info
        if (in_trust_store) {
            // we only need to validate validity restrictions for trusted certificates, no signature, so abort here
            return CertificateValidity::valid();
        } else if (get_type(current_cert.signer_info) != SignerInfoType::Certificate_Digest_With_SHA256) {
            return CertificateInvalidReason::INVALID_SIGNER;
        }

        HashedId8 signer_hash = boost::get<HashedId8>(current_cert.signer_info);

        // try to extract ECDSA signature
        boost::optional<EcdsaSignature> sig = extract_ecdsa_signature(current_cert.signature);
        if (!sig) {
            return CertificateInvalidReason::MISSING_SIGNATURE;
        }

        // create buffer of certificate
        ByteBuffer binary_cert = convert_for_signing(current_cert);
        bool signer_found = false;

        for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
            auto verification_key = get_public_key(possible_signer);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_time_consistency(current_cert, possible_signer)) {
                    return CertificateInvalidReason::BROKEN_TIME_PERIOD;
                }

                current_cert = possible_signer;
                in_trust_store = true;
                signer_found = true;

                break;
            }
        }

        if (signer_found) {
            continue;
        }

        for (auto& possible_signer : m_cert_cache.lookup(signer_hash)) {
            auto verification_key = get_public_key(possible_signer);
            if (!verification_key) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_time_consistency(current_cert, possible_signer)) {
                    return CertificateInvalidReason::BROKEN_TIME_PERIOD;
                }

                current_cert = possible_signer;
                signer_found = true;

                break;
            }
        }

        if (signer_found) {
            continue;
        }

        return CertificateInvalidReason::UNKNOWN_SIGNER;
    }

    return CertificateInvalidReason::EXCESSIVE_CHAIN_LENGTH;
}

} // namespace security
} // namespace vanetza
