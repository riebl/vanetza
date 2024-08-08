#pragma once
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <list>

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
     * Get own certificate chain in root CA → AA → AT order, excluding the AT and root certificate
     * \return own certificate chain
     */
    virtual std::list<Certificate> own_chain() = 0;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const ecdsa256::PrivateKey& own_private_key() = 0;

    virtual ~CertificateProvider() = default;
};

} // namespace v2
} // namespace security
} // namespace vanetza

