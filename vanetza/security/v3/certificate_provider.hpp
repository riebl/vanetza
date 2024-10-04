#pragma once
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

class CertificateProvider
{
public:
    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const Certificate& own_certificate() = 0;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const PrivateKey& own_private_key() = 0;

    /**
     * Get certificate cache
     * \return certificate cache
     */
    virtual CertificateCache& cache() = 0;
    virtual const CertificateCache& cache() const = 0;

    virtual ~CertificateProvider() = default;
};

class BaseCertificateProvider : public CertificateProvider
{
public:
    const CertificateCache& cache() const override { return m_cache; }
    CertificateCache& cache() override { return m_cache; }
    
private:
    CertificateCache m_cache;
};

} // namespace v3
} // namespace security
} // namespace vanetza
