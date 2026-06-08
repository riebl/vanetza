#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <vanetza/security/v3/geometry.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <vanetza/security/v3/revocation_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <algorithm>
#include <cstdint>


namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

bool check_time_consistency(const CertificateView& subject, const CertificateView& issuer)
{
    const auto subject_time = subject.get_start_and_end_validity();
    const auto issuer_time = issuer.get_start_and_end_validity();
    return issuer_time.start_validity <= subject_time.start_validity &&
        issuer_time.end_validity >= subject_time.end_validity;
}

bool check_permission_consistency(const CertificateView& subject, const CertificateView& issuer, ItsAid its_aid)
{
    const auto* subject_cert = subject.raw_certificate();
    const auto* issuer_cert = issuer.raw_certificate();
    if (!subject_cert || !issuer_cert) {
        return false;
    }

    const auto subject_aids = subject.is_ca_certificate() ? get_issuer_aids(*subject_cert) : get_aids(*subject_cert);
    if (subject_aids.empty() && subject_cert->toBeSigned.certIssuePermissions) {
        // "all" permissions.
    } else if (std::find(subject_aids.begin(), subject_aids.end(), its_aid) == subject_aids.end()) {
        return false;
    }

    const auto issuer_aids = get_issuer_aids(*issuer_cert);
    if (issuer_aids.empty() && issuer_cert->toBeSigned.certIssuePermissions) {
        return true;
    }

    return std::find(issuer_aids.begin(), issuer_aids.end(), its_aid) != issuer_aids.end();
}

bool check_assurance_consistency(const CertificateView& subject, const CertificateView& issuer)
{
    const auto* subject_cert = subject.raw_certificate();
    const auto* issuer_cert = issuer.raw_certificate();
    if (!subject_cert || !issuer_cert) {
        return false;
    }

    const auto* subject_assurance = subject_cert->toBeSigned.assuranceLevel;
    const auto* issuer_assurance = issuer_cert->toBeSigned.assuranceLevel;
    if (!subject_assurance) {
        return true;
    } else if (!issuer_assurance || subject_assurance->size == 0 || issuer_assurance->size == 0) {
        return false;
    }

    const std::uint8_t subject_value = subject_assurance->buf[0];
    const std::uint8_t issuer_value = issuer_assurance->buf[0];
    const std::uint8_t subject_level = (subject_value >> 5) & 0x07;
    const std::uint8_t issuer_level = (issuer_value >> 5) & 0x07;
    const std::uint8_t subject_confidence = (subject_value >> 2) & 0x07;
    const std::uint8_t issuer_confidence = (issuer_value >> 2) & 0x07;

    return subject_level < issuer_level ||
        (subject_level == issuer_level && subject_confidence <= issuer_confidence);
}

bool equal(const asn1::TwoDLocation& lhs, const asn1::TwoDLocation& rhs)
{
    return lhs.latitude == rhs.latitude && lhs.longitude == rhs.longitude;
}

bool equal(const asn1::RectangularRegion& lhs, const asn1::RectangularRegion& rhs)
{
    return equal(lhs.northWest, rhs.northWest) && equal(lhs.southEast, rhs.southEast);
}

bool equal(const asn1::SequenceOfRectangularRegion& lhs, const asn1::SequenceOfRectangularRegion& rhs)
{
    if (lhs.list.count != rhs.list.count) {
        return false;
    }

    for (int i = 0; i < lhs.list.count; ++i) {
        if (!lhs.list.array[i] || !rhs.list.array[i] || !equal(*lhs.list.array[i], *rhs.list.array[i])) {
            return false;
        }
    }

    return true;
}

bool is_within(const asn1::GeographicRegion& inner, const asn1::CircularRegion& outer)
{
    if (inner.present != Vanetza_Security_GeographicRegion_PR_circularRegion) {
        return false;
    }

    const auto& circle = inner.choice.circularRegion;
    if (!is_valid(circle.center) || !is_valid(outer.center) || circle.radius < 0 || outer.radius < 0) {
        return false;
    }

    PositionFix inner_center;
    inner_center.latitude = convert_latitude(circle.center.latitude);
    inner_center.longitude = convert_longitude(circle.center.longitude);
    return distance(inner_center, outer.center) + circle.radius * units::si::meter <= outer.radius * units::si::meter;
}

bool is_within(const asn1::GeographicRegion& inner, const asn1::SequenceOfRectangularRegion& outer)
{
    return inner.present == Vanetza_Security_GeographicRegion_PR_rectangularRegion &&
        equal(inner.choice.rectangularRegion, outer);
}

bool is_within(const asn1::GeographicRegion&, const asn1::PolygonalRegion&)
{
    return false;
}

bool is_within(const asn1::GeographicRegion& inner, const asn1::GeographicRegion& outer)
{
    switch (outer.present) {
        case Vanetza_Security_GeographicRegion_PR_circularRegion:
            return is_within(inner, outer.choice.circularRegion);
        case Vanetza_Security_GeographicRegion_PR_rectangularRegion:
            return is_within(inner, outer.choice.rectangularRegion);
        case Vanetza_Security_GeographicRegion_PR_polygonalRegion:
            return is_within(inner, outer.choice.polygonalRegion);
        case Vanetza_Security_GeographicRegion_PR_NOTHING:
            return true;
        default:
            return false;
    }
}

bool check_region_consistency(const CertificateView& subject, const CertificateView& issuer)
{
    const auto* subject_cert = subject.raw_certificate();
    const auto* issuer_cert = issuer.raw_certificate();
    if (!subject_cert || !issuer_cert) {
        return false;
    }

    const auto* issuer_region = issuer_cert->toBeSigned.region;
    const auto* subject_region = subject_cert->toBeSigned.region;
    if (!issuer_region) {
        return true;
    } else if (!subject_region) {
        return false;
    } else {
        return is_within(*subject_region, *issuer_region);
    }
}

} // namespace

auto DefaultCertificateValidator::valid_for_signing(const CertificateView& signing_cert, ItsAid its_aid) -> Verdict
{
    if (!m_disable_time_checks && !m_runtime) {
        return Verdict::Misconfiguration;
    } else if (!m_disable_location_checks && (!m_position_provider || !m_location_checker)) {
        return Verdict::Misconfiguration;
    } else if (!signing_cert.valid_for_application(its_aid)) {
        return Verdict::InsufficientPermission;
    } else if (m_runtime && !signing_cert.valid_at_timepoint(m_runtime->now())) {
        return Verdict::Expired;
    } else if (!is_chain_anchored(signing_cert)) {
        return Verdict::Untrusted;
    } else if (!chain_is_consistent(signing_cert, its_aid)) {
        return Verdict::Unknown;
    } else if (chain_is_revoked(signing_cert)) {
        return Verdict::Revoked;
    } else {
        Verdict verdict = Verdict::Valid;
        if (!m_disable_location_checks) {
            if (m_position_provider) {
                auto location = m_position_provider->position_fix();
                if (signing_cert.has_region_restriction()) {
                    if (!signing_cert.valid_at_location(location, m_location_checker)) {
                        verdict = Verdict::OutsideRegion;
                    }
                } else {
                    auto issuing_cert = find_issuer_certificate(signing_cert);
                    if (issuing_cert && !issuing_cert->valid_at_location(location, m_location_checker)) {
                        verdict = Verdict::OutsideRegion;
                    }
                }
            }
        }
        return verdict;
    }
}

void DefaultCertificateValidator::use_runtime(const Runtime* runtime)
{
    m_runtime = runtime;
}

void DefaultCertificateValidator::use_position_provider(PositionProvider* pp)
{
    m_position_provider = pp;
}

void DefaultCertificateValidator::use_issuer_lookup(const IssuerLookup* lookup)
{
    m_issuer_lookup = lookup;
}

void DefaultCertificateValidator::use_location_checker(const LocationChecker* checker)
{
    m_location_checker = checker;
}

void DefaultCertificateValidator::use_revocation_lookup(const RevocationLookup* lookup)
{
    m_revocation_lookup = lookup;
}

void DefaultCertificateValidator::use_trust_store(const TrustStore* store)
{
    m_trust_store = store;
}

void DefaultCertificateValidator::disable_time_checks(bool flag)
{
    m_disable_time_checks = flag;
}

void DefaultCertificateValidator::disable_location_checks(bool flag)
{
    m_disable_location_checks = flag;
}

const Certificate* DefaultCertificateValidator::find_issuer_certificate(const CertificateView& at_cert) const
{
    if (m_issuer_lookup) {
        auto maybe_issuer_digest = at_cert.issuer_digest();
        if (maybe_issuer_digest) {
            return m_issuer_lookup->find_issuer(*maybe_issuer_digest);
        }
    }

    return nullptr;
}

bool DefaultCertificateValidator::is_chain_anchored(const CertificateView& signing_cert) const
{
    if (!m_trust_store || !m_issuer_lookup) {
        // No anchoring policy configured: fail open, matching the existing optional-injection pattern.
        return true;
    }

    constexpr int max_chain_depth = 8;
    const CertificateView* cert = &signing_cert;
    for (int depth = 0; depth < max_chain_depth; ++depth) {
        if (cert->issuer_is_self()) {
            // Reached a self-signed cert: anchored iff it's in the trust store.
            const auto cert_digest = cert->calculate_digest();
            return cert_digest && !m_trust_store->lookup(*cert_digest).empty();
        }
        const auto issuer_digest = cert->issuer_digest();
        if (!issuer_digest) {
            return false;
        }
        const Certificate* issuer = m_issuer_lookup->find_issuer(*issuer_digest);
        if (!issuer) {
            return false;
        }
        cert = issuer;
    }
    return false;
}

bool DefaultCertificateValidator::chain_is_consistent(const CertificateView& signing_cert, ItsAid its_aid) const
{
    if (!m_issuer_lookup) {
        return true;
    }

    constexpr int max_chain_depth = 8;
    const CertificateView* subject = &signing_cert;
    for (int depth = 0; depth < max_chain_depth && !subject->issuer_is_self(); ++depth) {
        const Certificate* issuer = find_issuer_certificate(*subject);
        if (!issuer) {
            return true;
        }
        if (!check_consistency(*subject, *issuer, its_aid)) {
            return false;
        }
        subject = issuer;
    }

    return true;
}

bool DefaultCertificateValidator::chain_is_revoked(const CertificateView& signing_cert) const
{
    if (!m_revocation_lookup || !m_issuer_lookup) {
        return false;
    }

    // C-ITS chains are AT -> AA -> RCA (depth 3). The bound is defense against IssuerLookup cycles.
    // The walk stops at the self-signed root: RCA revocation is the ECTL's job, not a CRL's.
    constexpr int max_chain_depth = 8;
    const CertificateView* cert = &signing_cert;
    for (int depth = 0; depth < max_chain_depth; ++depth) {
        const auto cert_digest = cert->calculate_digest();
        const auto issuer_digest = cert->issuer_digest();
        if (!cert_digest || !issuer_digest) {
            break;
        }
        if (m_revocation_lookup->is_revoked(*issuer_digest, *cert_digest)) {
            return true;
        }
        const Certificate* issuer = m_issuer_lookup->find_issuer(*issuer_digest);
        if (!issuer || issuer->issuer_is_self()) {
            break;
        }
        cert = issuer;
    }
    return false;
}

bool DefaultCertificateValidator::check_consistency(
    const CertificateView& subject, const CertificateView& issuer, ItsAid its_aid) const
{
    return check_time_consistency(subject, issuer) &&
        check_permission_consistency(subject, issuer, its_aid) &&
        check_assurance_consistency(subject, issuer) &&
        check_region_consistency(subject, issuer);
}

} // namespace v3
} // namespace security
} // namespace vanetza
