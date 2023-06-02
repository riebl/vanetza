#ifndef DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX
#define DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_validator.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
class TrustStore;
class CertificateCache;
class TrustStoreV3;
class CertificateCacheV3;


/**
 * \brief The default certificate validator
 *
 * This certificate validator is reasonably secure! It just doesn't implement revocation checks for CA certificates.
 */
class DefaultCertificateValidator : public CertificateValidator
{
public:
    DefaultCertificateValidator(Backend&, CertificateCache&, const TrustStore&);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const CertificateVariant& certificate) override;
    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate);
    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const CertificateV3& certificate);

private:
    Backend& m_crypto_backend;
    CertificateCache& m_cert_cache;
    const TrustStore& m_trust_store;
};

} // namespace security
} // namespace vanetza

#endif /* DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX */
