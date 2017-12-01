#ifndef NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX
#define NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX

#include <string>
#include <vanetza/common/clock.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A very simplistic certificate provider
 *
 * This certificate provider signs its certificates with a randomly generated root certificate. This means the
 * signatures produced based on this certificate provider can't be verified by other parties.
 *
 * It's intended for experimenting with secured messages without validating signatures.
 */
class NaiveCertificateProvider : public CertificateProvider
{
public:
    NaiveCertificateProvider(const Clock::time_point& time_now);

    /**
     * \brief get own certificate for signing
     * \return own certificate
     */
    const Certificate& own_certificate() override;

    /**
     * \brief get own private key
     * \return private key
     */
    const ecdsa256::PrivateKey& own_private_key() override;

    /**
     * \brief get signer certificate
     * \return signing root certificate
     */
    const Certificate& root_certificate();

private:
    /**
     * \brief generate a authorization ticket
     *
     * \return generated certificate
     */
    Certificate generate_authorization_ticket();

    /**
     * \brief generate a root certificate
     *
     * \return generated certificate
     */
    Certificate generate_root_certificate();

    /**
     * \brief retrieve common root key pair (for all instances)
     * \return root key pair
     */
    const ecdsa256::KeyPair& root_key_pair();

    BackendCryptoPP m_crypto_backend; /*< key generation is not a generic backend feature */
    const Clock::time_point& m_time_now;
    const std::string m_root_certificate_subject;
    const Certificate m_root_certificate;
    const HashedId8 m_root_certificate_hash;
    const ecdsa256::KeyPair& m_root_key_pair;
    const ecdsa256::KeyPair m_own_key_pair;
    Certificate m_own_certificate;
};

} // namespace security
} // namespace vanetza

#endif /* NAIVE_CERTIFICATE_PROVIDER_HPP_MTULFLKX */
