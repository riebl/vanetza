#ifndef SECURITY_ENTITY_HPP
#define SECURITY_ENTITY_HPP

#include <vanetza/common/runtime.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
class Backend;
class CertificateManager;

class SecurityEntity
{
public:
    /**
     * \param rt runtime providing current time among others
     * \param backend for cryptographic operations
     * \param manager certificate manager
     */
    SecurityEntity(Runtime& rt, Backend& backend, CertificateManager& manager);
    ~SecurityEntity();

    /**
     * \brief Creates a security envelope covering the given payload.
     *
     * The payload consists of the CommonHeader, ExtendedHeader and the payload of
     * the layers above the network layer. The entire security envelope is used
     * to calculate a signature which gets added to the resulting SecuredMessage.
     *
     * \param request containing payload to sign
     * \return confirmation containing signed SecuredMessage
     */
    EncapConfirm encapsulate_packet(const EncapRequest& encap_request);

    /** \brief decapsulates packet
     *
     * \param packet that should be decapsulated
     * \return decapsulated packet
     */

    /**
     * \brief Decapsulates the payload within a SecuredMessage
     *
     * Verifies the Signature and SignerInfo of a SecuredMessage.
     *
     * \param request containing a SecuredMessage
     * \return decapsulation confirmation including plaintext payload
     */
    DecapConfirm decapsulate_packet(const DecapRequest& decap_request);

    /**
     * \brief enable deferred signature creation
     *
     * SecuredMessages contain EcdsaSignatureFuture instead of EcdsaSignature
     * when this feature is enabled.
     *
     * \param flag true for enabling deferred signature calculation
     */
    void enable_deferred_signing(bool flag);

private:
    Runtime& m_runtime;
    CertificateManager& m_certificate_manager;
    Backend& m_crypto_backend;
    SignService m_sign_service;
    VerifyService m_verify_service;
};

} // namespace security
} // namespace vanetza

#endif // SECURITY_ENTITY_HPP
