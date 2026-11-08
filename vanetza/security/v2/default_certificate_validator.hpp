#ifndef DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX
#define DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/v2/certificate_validator.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
class CryptoProvider;

namespace v2
{

// forward declaration
class TrustStore;
class CertificateCache;

/**
 * \brief The default certificate validator
 *
 * This certificate validator is reasonably secure! It just doesn't implement revocation checks for CA certificates.
 */
class DefaultCertificateValidator : public CertificateValidator
{
public:
    DefaultCertificateValidator(CryptoProvider&, CertificateCache&, const TrustStore&);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate) override;

private:
    CryptoProvider& m_crypto;
    CertificateCache& m_cert_cache;
    const TrustStore& m_trust_store;
};

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX */
