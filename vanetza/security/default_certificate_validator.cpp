#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/trust_store.hpp>
#include <algorithm>
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

    for (auto& validity_restriction : certificate.validity_restriction) {
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

std::list<ItsAid> extract_application_identifiers(const Certificate& certificate)
{
    std::list<ItsAid> aids;

    auto certificate_type = certificate.subject_info.subject_type;
    if (certificate_type == SubjectType::Authorization_Ticket) {
        auto list = certificate.get_attribute<SubjectAttributeType::Its_Aid_Ssp_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.its_aid.get());
            }
        }
    } else {
        auto list = certificate.get_attribute<SubjectAttributeType::Its_Aid_List>();
        if (list) {
            for (auto& item : *list) {
                aids.push_back(item.get());
            }
        }
    }

    return aids;
}

bool check_permission_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_aids = extract_application_identifiers(certificate);
    auto signer_aids = extract_application_identifiers(signer);
    auto compare = [](ItsAid a, ItsAid b) { return a < b; };

    certificate_aids.sort(compare);
    signer_aids.sort(compare);

    return std::includes(signer_aids.begin(), signer_aids.end(), certificate_aids.begin(), certificate_aids.end());
}

bool check_subject_assurance_consistency(const Certificate& certificate, const Certificate& signer)
{
    auto certificate_assurance = certificate.get_attribute<SubjectAttributeType::Assurance_Level>();
    auto signer_assurance = signer.get_attribute<SubjectAttributeType::Assurance_Level>();

    if (!certificate_assurance || !signer_assurance) {
        return false;
    }

    // See TS 103 096-2 v1.3.1, section 5.2.7.11 + 5.3.5.17 and following
    if (certificate_assurance->assurance() > signer_assurance->assurance()) {
        return false;
    } else if (certificate_assurance->assurance() == signer_assurance->assurance()) {
        if (certificate_assurance->confidence() > signer_assurance->confidence()) {
            return false;
        }
    }

    return true;
}

bool check_consistency(const Certificate& certificate, const Certificate& signer)
{
    if (!check_time_consistency(certificate, signer)) {
        return false;
    }

    if (!check_permission_consistency(certificate, signer)) {
        return false;
    }

    if (!check_subject_assurance_consistency(certificate, signer)) {
        return false;
    }

    return true;
}

} // namespace

DefaultCertificateValidator::DefaultCertificateValidator(Backend& backend, const Clock::time_point& time_now,
        PositionProvider& positioning, const TrustStore& trust_store, CertificateCache& cert_cache) :
    m_crypto_backend(backend),
    m_time_now(time_now),
    m_position_provider(positioning),
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

        if (!check_region(current_cert)) {
            return CertificateInvalidReason::OFF_REGION;
        }

        if (!certificate.get_attribute<SubjectAttributeType::Assurance_Level>()) {
            return CertificateInvalidReason::MISSING_SUBJECT_ASSURANCE;
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

        // TODO check if certificate has been revoked for all CA certificates, ATs are never revoked

        for (auto& possible_signer : m_trust_store.lookup(signer_hash)) {
            auto verification_key = get_public_key(possible_signer);
            if (!verification_key) {
                continue;
            }

            const auto signer_type = possible_signer.subject_info.subject_type;
            if (signer_type != SubjectType::Authorization_Authority && signer_type != SubjectType::Root_Ca) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(current_cert, possible_signer)) {
                    return CertificateInvalidReason::INCONSISTENT_WITH_SIGNER;
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

            const auto signer_type = possible_signer.subject_info.subject_type;
            if (signer_type != SubjectType::Authorization_Authority && signer_type != SubjectType::Root_Ca) {
                continue;
            }

            if (m_crypto_backend.verify_data(verification_key.get(), binary_cert, sig.get())) {
                if (!check_consistency(current_cert, possible_signer)) {
                    return CertificateInvalidReason::INCONSISTENT_WITH_SIGNER;
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

bool DefaultCertificateValidator::check_region(const Certificate& certificate)
{
    using namespace boost::units;
    const PositionFix& position_fix = m_position_provider.position_fix();
    TwoDLocation ego_position(position_fix.latitude, position_fix.longitude);

    for (auto& restriction : certificate.validity_restriction) {
        ValidityRestriction validity_restriction = restriction;
        ValidityRestrictionType type = get_type(validity_restriction);

        if (type == ValidityRestrictionType::Region) {
            GeographicRegion region = boost::get<GeographicRegion>(validity_restriction);
            RegionType region_type = get_type(region);

            if (region_type == RegionType::None) {
                continue;
            }

            if (!position_fix.confidence) {
                return false; // cannot check region restrictions without good position fix
            } else if (region_type == RegionType::Circle) {
                CircularRegion circular_region = boost::get<CircularRegion>(region);
                return is_within(ego_position, circular_region);
            } else if (region_type == RegionType::Rectangle) {
                std::list<RectangularRegion> region_rectangles = boost::get<std::list<RectangularRegion>>(region);
                static const unsigned max_rectangles = 6; // see TS 103 097 v1.2.1, section 4.2.20
                if (region_rectangles.size() > max_rectangles) {
                    return false;
                }

                return std::any_of(region_rectangles.begin(), region_rectangles.end(),
                        [&ego_position](const RectangularRegion& rect) { return is_within(ego_position, rect); });
            }

            // TODO: Add support for polygonal region, see TS 103 097 v1.2.1, section 4.2.24
            // TODO: Add support for identified region, see TS 103 097 v1.2.1, section 4.2.25

            // unsupported region restriction
            return false;
        }
    }

    return true;
}

} // namespace security
} // namespace vanetza
