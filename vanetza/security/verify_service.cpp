#include <vanetza/security/verify_service.hpp>
namespace vanetza
{
namespace security
{

DummyVerifyService::DummyVerifyService(VerificationReport report, CertificateValidity validity) :
    m_report(report), m_validity(validity)
{
}

VerifyConfirm DummyVerifyService::verify(const VerifyRequest& request)
{
    VerifyConfirm confirm;
    confirm.report = m_report;
    confirm.certificate_validity = m_validity;
    if (request.secured_message) {
        confirm.its_aid = get_its_aid(*request.secured_message);
    }
    return confirm;
}

} // namespace security
} // namespace vanetza
