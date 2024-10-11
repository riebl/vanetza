#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

auto DefaultCertificateValidator::valid_for_signing(const Certificate& signing_cert, ItsAid its_aid) -> Verdict
{
    if (!m_disable_time_checks && !m_runtime) {
        return Verdict::Misconfiguration;
    } else if (!m_disable_location_checks && !m_position_provider) {
        return Verdict::Misconfiguration;
    } else if (!signing_cert.valid_for_application(its_aid)) {
        return Verdict::InsufficientPermission;
    } else if (m_position_provider && !signing_cert.valid_at_location(m_position_provider->position_fix())) {
        return Verdict::OutsideRegion;
    } else if (m_runtime && !signing_cert.valid_at_timepoint(m_runtime->now())) {
        return Verdict::Expired;
    } else {
        return Verdict::Valid;
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

void DefaultCertificateValidator::disable_time_checks(bool flag)
{
    m_disable_time_checks = flag;
}

void DefaultCertificateValidator::disable_location_checks(bool flag)
{
    m_disable_location_checks = flag;
}

} // namespace v3
} // namespace security
} // namespace vanetza
