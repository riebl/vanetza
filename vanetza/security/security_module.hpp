#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_view.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/common/factory.hpp>
#include <vanetza/security/aes.hpp>
#include <vanetza/security/encrypted_symmetric_key.hpp>
#include <vanetza/security/hmac.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/signature.hpp>
#include <memory>
#include <string>

namespace vanetza
{
namespace security
{

class SecurityModule
{
public:
    virtual ~SecurityModule() = default;

    /**
     * Create a key pair for signing
     * \param type curve of key pair
     * \return reference to created private key or error, see SecurityModuleError for conditions
     */
    virtual expected<KeyReference> create_signing_key(KeyType type) = 0;

    /**
     * Find reference of a stored private key usable for signing
     * \param key public key of the private key
     * \return reference or error, e.g. KeyNotFound by a module without key storage,
     *         see SecurityModuleError for conditions
     */
    virtual expected<KeyReference> find_signing_key(const PublicKey& key) = 0;

    /**
     * Get public key matching a referenced private key
     * \param key reference to private key
     * \return public key or error, see SecurityModuleError for conditions
     */
    virtual expected<PublicKey> public_key(const KeyReference& key) = 0;

    /**
     * Sign a digest
     * \param digest hash value of data
     * \param key reference to private key
     * \return signature or error, see SecurityModuleError for conditions
     */
    virtual expected<Signature> sign(const ByteBuffer& digest, const KeyReference& key) = 0;

    /**
     * Release module resources of a referenced private key
     * \param key reference to private key
     * \return false if releasing resources failed
     */
    virtual bool discard_key(const KeyReference& key) = 0;

    /**
     * Generate a random AES key, e.g. a session key for a request to a PKI authority
     * \return key or error, see SecurityModuleError for conditions
     */
    virtual expected<Aes128Key> generate_aes_key() = 0;

    /**
     * Generate a random HMAC key, e.g. hmacKey of an authorization request (ETSI TS 102 941 §6.2.3.3.1)
     * \return key or error, see SecurityModuleError for conditions
     */
    virtual expected<HmacKey> generate_hmac_key() = 0;

    /**
     * Encrypt a symmetric key for a recipient by ECIES with a fresh ephemeral key
     * \param recipient public encryption key of recipient
     * \param key symmetric key
     * \param info key derivation parameter, i.e. hash of recipient's certificate
     * \return encrypted key or error, see SecurityModuleError for conditions
     */
    virtual expected<EncryptedSymmetricKey> encrypt_key(
        const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info) = 0;
};

/**
 * \brief get factory containing builtin security module implementations
 *
 * Included set of modules depends on CMake build configuration, it may be empty.
 * Modules are created with their default configuration, e.g. without credential storage.
 * \return factory
 */
const Factory<SecurityModule>& builtin_security_modules();

/**
 * \brief create a security module instance
 *
 * Name "default" selects the module preferred by this build.
 * \param name identifying name of module implementation
 * \param factory build module registered by name from this factory
 * \return module instance or nullptr if unavailable
 */
std::unique_ptr<SecurityModule> create_security_module(
    const std::string& name = "default", const Factory<SecurityModule>& factory = builtin_security_modules());

} // namespace security
} // namespace vanetza
