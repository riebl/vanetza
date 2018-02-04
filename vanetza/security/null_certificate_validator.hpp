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

    DecapConfirm check_certificate(const Certificate&) override;

    /**
     * Set predefined result of check_certificate() calls
     * \param result predefined result
     */
    void certificate_check_result(const DecapConfirm& result);

private:
    DecapConfirm m_check_result;
};

} // namespace security
} // namespace vanetza

#endif /* NULL_CERTIFICATE_VALIDATOR_HPP_3L9RJY2A */
