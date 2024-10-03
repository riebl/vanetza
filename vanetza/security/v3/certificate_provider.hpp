#pragma once
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/v3/certificate.hpp>

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

    virtual ~CertificateProvider() = default;
};

} // namespace v2
} // namespace security
} // namespace vanetza

