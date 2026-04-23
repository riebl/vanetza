#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>

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
    confirm.its_aid = get_its_aid(request.secured_message);

    struct MessageVisitor : boost::static_visitor<>
    {
        MessageVisitor(DummyVerifyService& service, VerifyConfirm& confirm) : 
            m_service(service), m_confirm(confirm)
        {
        }

        void operator()(const v2::SecuredMessage& msg)
        {
            // not implemented for v2
        }

        void operator()(const v3::SecuredMessage& msg)
        {
            auto signer = msg.signer_identifier();
            m_confirm.certificate_id = v3::get_certificate_id(signer);

            if (m_confirm.certificate_id) {
                if (m_service.m_cert_cache) {
                    if (auto cert = v3::get_certificate(signer)) {
                        m_service.m_cert_cache->store(v3::Certificate { *cert });
                        m_confirm.permissions = v3::get_app_permissions(*cert, m_confirm.its_aid);
                    } else if (auto cert = m_service.m_cert_cache->lookup(*m_confirm.certificate_id)) {
                        m_confirm.permissions = v3::get_app_permissions(*cert->content(), m_confirm.its_aid);
                    }
                } else if (auto cert = v3::get_certificate(signer)) {
                    m_confirm.permissions = v3::get_app_permissions(*cert, m_confirm.its_aid);
                }
            }
        }

        DummyVerifyService& m_service;
        VerifyConfirm& m_confirm;
    } visitor(*this, confirm);
    boost::apply_visitor(visitor, request.secured_message);

    return confirm;
}

void DummyVerifyService::use_certificate_cache(v3::CertificateCache* cache)
{
    m_cert_cache = cache;
}

} // namespace security
} // namespace vanetza
