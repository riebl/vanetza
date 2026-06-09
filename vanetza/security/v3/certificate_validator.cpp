#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <vanetza/security/v3/revocation_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
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
    if (subject.is_ca_certificate() && !subject.is_allowed_to_issue(its_aid)) {
        return false;
    } else if (subject.is_at_certificate() && !subject.valid_for_application(its_aid)) {
        return false;
    }

    return issuer.is_allowed_to_issue(its_aid);
}

bool check_assurance_consistency(const CertificateView& subject, const CertificateView& issuer)
{
    const auto subject_assurance = subject.assurance_level();
    const auto issuer_assurance = issuer.assurance_level();
    if (!subject_assurance) {
        return true;
    } else if (!issuer_assurance) {
        return false;
    }

    const auto subject_value = *subject_assurance;
    const auto issuer_value = *issuer_assurance;
    const std::uint8_t subject_level = (subject_value >> 5) & 0x07;
    const std::uint8_t issuer_level = (issuer_value >> 5) & 0x07;
    const std::uint8_t subject_confidence = (subject_value >> 2) & 0x07;
    const std::uint8_t issuer_confidence = (issuer_value >> 2) & 0x07;

    return subject_level < issuer_level ||
        (subject_level == issuer_level && subject_confidence <= issuer_confidence);
}

bool check_region_consistency(const CertificateView& subject, const CertificateView& issuer)
{
    return subject.region_is_within(issuer);
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

void DefaultCertificateValidator::disable_chain_consistency_checks(bool flag)
{
    m_disable_chain_consistency_checks = flag;
}

void DefaultCertificateValidator::disable_region_consistency_checks(bool flag)
{
    m_disable_region_consistency_checks = flag;
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
    if (m_disable_chain_consistency_checks) {
        return true;
    }

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
        (m_disable_region_consistency_checks || check_region_consistency(subject, issuer));
}

} // namespace v3
} // namespace security
} // namespace vanetza
