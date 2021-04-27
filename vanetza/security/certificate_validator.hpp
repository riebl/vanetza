#ifndef CERTIFICATE_VALIDATOR_HPP
#define CERTIFICATE_VALIDATOR_HPP

#include <vanetza/security/certificate.hpp>

namespace vanetza
{
namespace security
{

class CertificateValidator
{
public:
    /**
     * Check validity of given certificate and consistency with parent certificates.
     * \param certificate given certificate
     * \return validity result
     */
    virtual CertificateValidity check_certificate(const Certificate& certificate) = 0;

    virtual ~CertificateValidator() = default;
};

class CertificateValidatorV3
{
public:
    /**
     * Check validity of given certificate and consistency with parent certificates.
     * \param certificate given certificate
     * \return validity result
     */
    virtual CertificateValidity check_certificate(const CertificateV3& certificate) = 0;

    virtual ~CertificateValidatorV3() = default;
};


} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_VALIDATOR_HPP
