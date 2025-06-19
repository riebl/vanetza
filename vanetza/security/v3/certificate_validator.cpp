#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>

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
    } else if (!m_disable_location_checks && !m_position_provider) {
        return Verdict::Misconfiguration;
    } else if (!signing_cert.valid_for_application(its_aid)) {
        return Verdict::InsufficientPermission;
    } else if (m_runtime && !signing_cert.valid_at_timepoint(m_runtime->now())) {
        return Verdict::Expired;
    } else {
        Verdict verdict = Verdict::Valid;
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

void DefaultCertificateValidator::use_certificate_cache(const CertificateCache* cache)
{
    m_certificate_cache = cache;
}

void DefaultCertificateValidator::use_location_checker(const LocationChecker* checker)
{
    m_location_checker = checker;
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
    if (m_certificate_cache) {
        auto maybe_issuer_digest = at_cert.issuer_digest();
        if (maybe_issuer_digest) {
            return m_certificate_cache->lookup(*maybe_issuer_digest);
        }
    }

    return nullptr;
}

} // namespace v3
} // namespace security
} // namespace vanetza
