#ifndef BASIC_CERTIFICATE_MANAGER_HPP_MTULFLKX
#define BASIC_CERTIFICATE_MANAGER_HPP_MTULFLKX

#include <vanetza/common/clock.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate_manager.hpp>

namespace vanetza
{
namespace security
{

/**
 * \brief A very simplistic certificate manager
 *
 * This certificate manager is INSECURE!
 * It's only okay for experimenting with flawed secured messages.
 */
class BasicCertificateManager : public CertificateManager
{
public:
    BasicCertificateManager(const Clock::time_point& time_now, const Certificate& authorization_ticket, const ecdsa256::KeyPair& authorization_ticket_key, const Certificate& sign_cert);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate) override;

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

private:
    BackendCryptoPP crypto_backend;
    const Clock::time_point& time_now;
    ecdsa256::KeyPair authorization_ticket_key;
    Certificate authorization_ticket;
    Certificate sign_cert;
};

} // namespace security
} // namespace vanetza

#endif /* BASIC_CERTIFICATE_MANAGER_HPP_MTULFLKX */
