#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <vanetza/security/v3/revocation_lookup.hpp>


namespace vanetza
{
namespace security
{
namespace v3
{

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

} // namespace v3
} // namespace security
} // namespace vanetza
