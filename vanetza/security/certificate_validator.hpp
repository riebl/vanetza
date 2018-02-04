#ifndef CERTIFICATE_VALIDATOR_HPP
#define CERTIFICATE_VALIDATOR_HPP

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/verify_service.hpp>

namespace vanetza
{
namespace security
{

class CertificateValidator
{
public:
    /**
     * Check validity of given certificate
     * \param certificate given certificate
     * \return validity result
     */
    virtual DecapConfirm check_certificate(const Certificate& certificate) = 0;
};

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_VALIDATOR_HPP
