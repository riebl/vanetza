#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/certificate.hpp>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * \brief A Manager to handle Certificates using Crypto++
 * \todo rename to CryptoPPCertManager
 * \todo create a base class
 */
class CertificateManager
{
public:
    CertificateManager(const Clock::time_point& time_now);

    /**
     * \brief Verifies the Signature and SignerInfo of a SecuredMessage
     *
     * It also decapsulates the data from the SecuredMessage.
     *
     * \param request containing a SecuredMessage
     * \return decapsulation confirmation
     */
    DecapConfirm verify_message(const DecapRequest& request);

    /**
     * \brief generate a certificate
     *
     * \param key_pair keys used to create the certificate
     * \return generated certificate
     */
    Certificate generate_certificate(const ecdsa256::KeyPair& key_pair);

    /**
     * \brief check certificate
     * \param certificate to verify
     * \return certificate status
     */
    CertificateValidity check_certificate(const Certificate& certificate);

    /**
     * \brief get own certificate for signing
     * \return own certificate
     */
    const Certificate& own_certificate();

    /**
     * \brief get own private key
     * \return private key
     */
    const ecdsa256::PrivateKey& own_private_key();

private:
    /**
     * \brief get the current (system) time in microseconds
     * \return Time64
     */
    Time64 get_time();

    /**
     * \brief get the current (system) time in seconds
     * \return Time32
     */
    Time32 get_time_in_seconds();

    /** \brief retrieve common root key pair (for all instances)
     *
     * \note This is only a temporary workaround!
     * \return root key pair
     */
    const ecdsa256::KeyPair& get_root_key_pair();

    BackendCryptoPP m_crypto_backend;
    const Clock::time_point& m_time_now;
    const ecdsa256::KeyPair& m_root_key_pair;
    HashedId8 m_root_certificate_hash;
    ecdsa256::KeyPair m_own_key_pair;
    Certificate m_own_certificate;
};

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MANAGER_HPP
