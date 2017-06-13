#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>

namespace vanetza
{
namespace security
{

class CertificateManager
{
public:
    /**
     * Check validity of given certificate
     * \param cert given certificate
     * \return validity result
     */
    virtual CertificateValidity check_certificate(const Certificate&) = 0;

    /**
     * Get own certificate to use for signing
     * \return own certificate
     */
    virtual const Certificate& own_certificate() = 0;

    /**
     * Get private key associated with own certificate
     * \return private key
     */
    virtual const ecdsa256::PrivateKey& own_private_key() = 0;
};


} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MANAGER_HPP
