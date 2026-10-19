#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>

namespace vanetza
{
namespace security
{

namespace
{

/**
 * Get application permissions from v2 signer info, using the certificate cache if available
 *
 * The signer's certificate contained in the signer info is stored in the cache.
 * For a digest, the certificate is looked up from the cache instead.
 */
struct permissions_visitor : public boost::static_visitor<ByteBuffer>
{
    permissions_visitor(ItsAid aid, v2::CertificateCache* cache) :
        m_aid(aid), m_cache(cache) {}

    ByteBuffer operator()(std::nullptr_t) const
    {
        return ByteBuffer {};
    }

    ByteBuffer operator()(const HashedId8& digest) const
    {
        ByteBuffer permissions;
        if (m_cache) {
            // cache is keyed by SHA-256 hashes, which this digest is by definition
            std::list<v2::Certificate> cached = m_cache->lookup(digest, v2::SubjectType::Authorization_Ticket);
            if (!cached.empty()) {
                // use the first match arbitrarily
                permissions = v2::get_app_permissions(cached.front(), m_aid);
            }
        }
        return permissions;
    }

    ByteBuffer operator()(const v2::Certificate& cert) const
    {
        return permissions_of_signer(cert);
    }

    ByteBuffer operator()(const std::list<v2::Certificate>& chain) const
    {
        // last certificate in chain is the signer, its issuers are of no use without validation
        return chain.empty() ? ByteBuffer {} : permissions_of_signer(chain.back());
    }

    ByteBuffer operator()(const v2::CertificateDigestWithOtherAlgorithm&) const
    {
        // cannot look up digests of other hash algorithms in cache keyed by SHA-256
        return ByteBuffer {};
    }

private:
    /**
     * Remember signer's certificate and get its permissions
     * \param cert signer's certificate
     * \return application permissions of signer
     */
    ByteBuffer permissions_of_signer(const v2::Certificate& cert) const
    {
        if (m_cache) {
            m_cache->insert(cert);
        }
        return v2::get_app_permissions(cert, m_aid);
    }

    const ItsAid m_aid;
    v2::CertificateCache* const m_cache;
};

} // namespace

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

        void operator()(const v2::SecuredMessage& msg) const
        {
            const v2::SignerInfo* signer_info = msg.header_field<v2::HeaderFieldType::Signer_Info>();
            if (signer_info) {
                m_confirm.certificate_id = v2::get_certificate_id(*signer_info);
                permissions_visitor visitor(m_confirm.its_aid, m_service.m_v2_cert_cache);
                m_confirm.permissions = boost::apply_visitor(visitor, *signer_info);
            }
        }

        void operator()(const v3::SecuredMessage& msg)
        {
            auto signer = msg.signer_identifier();
            m_confirm.certificate_id = v3::get_certificate_id(signer);

            if (m_confirm.certificate_id) {
                if (m_service.m_v3_cert_cache) {
                    if (auto cert = v3::get_certificate(signer)) {
                        m_service.m_v3_cert_cache->store(v3::Certificate { *cert });
                        m_confirm.permissions = v3::get_app_permissions(*cert, m_confirm.its_aid);
                    } else if (auto cert = m_service.m_v3_cert_cache->lookup(*m_confirm.certificate_id)) {
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

void DummyVerifyService::use_certificate_cache(v2::CertificateCache* cache)
{
    m_v2_cert_cache = cache;
}

void DummyVerifyService::use_certificate_cache(v3::CertificateCache* cache)
{
    m_v3_cert_cache = cache;
}

} // namespace security
} // namespace vanetza
