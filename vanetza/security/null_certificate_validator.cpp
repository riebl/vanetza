#include <vanetza/security/null_certificate_validator.hpp>

namespace vanetza
{
namespace security
{

NullCertificateValidator::NullCertificateValidator() : m_reason(CertificateInvalidReason::UNKNOWN_SIGNER)
{
}

CertificateValidity NullCertificateValidator::check_certificate(const Certificate& certificate)
{
    return CertificateValidity(m_reason, certificate);
}

void NullCertificateValidator::certificate_check_result(const CertificateInvalidReason reason)
{
    m_reason = reason;
}

} // namespace security
} // namespace vanetza
