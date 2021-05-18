#ifndef CERTIFICATE_PROVIDER_HPP
#define CERTIFICATE_PROVIDER_HPP

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <list>

namespace vanetza
{
namespace security
{

class CertificateProvider
{
public:
    /**
     * Get the version of the provided certificates: 2 for v1.2.1 and 3 for v1.3.1
     * \return own certificate
     */
    virtual int version() = 0;

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const CertificateVariant& own_certificate() = 0;

    /**
     * Get own certificate chain in root CA → AA → AT order, excluding the AT and root certificate
     * \return own certificate chain
     */
    virtual std::list<CertificateVariant> own_chain() = 0;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const ecdsa256::PrivateKey& own_private_key() = 0;

    virtual ~CertificateProvider() = default;
};

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_PROVIDER_HPP
