#ifndef DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX
#define DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/position_vector.hpp>
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
    DecapConfirm check_certificate(const Certificate& certificate) override;

    /**
     * \brief Update local position vector
     * \note GN Address of given LongPositionVector is ignored!
     *
     * \param lpv Set positional data according to this argument
     */
    void update(const vanetza::geonet::LongPositionVector&);

private:
    Backend& m_crypto_backend;
    const Clock::time_point& m_time_now;
    const TrustStore& m_trust_store;
    CertificateCache& m_cert_cache;
    vanetza::geonet::LongPositionVector m_local_position_vector;

    bool check_region(const Certificate& certificate);
};

} // namespace security
} // namespace vanetza

#endif /* DEFAULT_CERTIFICATE_VALIDATOR_HPP_MTULFLKX */
