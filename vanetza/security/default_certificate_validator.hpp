#ifndef DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX
#define DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_validator.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
class TrustStore;
class CertificateCache;

/**
 * \brief A simplistic certificate validator
 *
 * This certificate validator is INSECURE! It doesn't implement all features, e.g. no revocation checks.
 */
class DefaultCertificateValidator : public CertificateValidator
{
public:
    DefaultCertificateValidator(Backend&, const Clock::time_point& time_now, const TrustStore&, CertificateCache&);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate) override;

private:
    Backend& m_crypto_backend;
    const Clock::time_point& m_time_now;
    const TrustStore& m_trust_store;
    CertificateCache& m_cert_cache;
};

} // namespace security
} // namespace vanetza

#endif /* DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX */
