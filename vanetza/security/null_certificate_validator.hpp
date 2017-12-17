#ifndef NULL_CERTIFICATE_VALIDATOR_HPP_3L9RJY2A
#define NULL_CERTIFICATE_VALIDATOR_HPP_3L9RJY2A

#include <vanetza/security/certificate_validator.hpp>

namespace vanetza
{
namespace security
{

class NullCertificateValidator : public CertificateValidator
{
public:
    NullCertificateValidator();

    CertificateValidity check_certificate(const Certificate& certificate) override;

    /**
     * Set predefined result of check_certificate() calls
     * \param result predefined result
     */
    void certificate_check_result(const CertificateInvalidReason reason);

private:
    CertificateInvalidReason m_reason;
};

} // namespace security
} // namespace vanetza

#endif /* NULL_CERTIFICATE_VALIDATOR_HPP_3L9RJY2A */
