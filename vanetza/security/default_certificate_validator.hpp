#ifndef DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX
#define DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate_validator.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A simplistic certificate validator
 *
 * This certificate validator is INSECURE! It doesn't implement all features, e.g. no revocation checks.
 */
class DefaultCertificateValidator : public CertificateValidator
{
public:
    DefaultCertificateValidator(const Clock::time_point& time_now, const Certificate& sign_cert);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate) override;

private:
    BackendCryptoPP crypto_backend;
    const Clock::time_point& time_now;
    ecdsa256::KeyPair authorization_ticket_key;
    Certificate authorization_ticket;
    Certificate sign_cert;
};

} // namespace security
} // namespace vanetza

#endif /* DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX */
