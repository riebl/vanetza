#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/security/aes.hpp>
#include <vanetza/security/encrypted_symmetric_key.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/signature.hpp>

namespace vanetza
{
namespace security
{

class SecurityModule
{
public:
    virtual ~SecurityModule() = default;
    virtual Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) = 0;
    virtual Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) = 0;

    /**
     * Verify signature of a SHA-256 or SHA-384 digest
     * \param digest hash value of signed data
     * \param signature signature of digest
     * \param key public key of signer
     * \return true for a valid signature, false for a signature not matching digest and key,
     *         or error, e.g. InvalidPublicKey, see SecurityModuleError for conditions
     */
    virtual expected<bool> verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& key) = 0;
    virtual expected<bool> verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& key) = 0;

    /**
     * Create a key pair for signing
     * \param type curve of key pair
     * \return reference to created private key or error, see SecurityModuleError for conditions
     */
    virtual expected<KeyReference> create_signing_key(KeyType type) = 0;

    /**
     * Find reference of a stored private key usable for signing
     * \param key public key of the private key
     * \return reference or error, see SecurityModuleError for conditions
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

    virtual ByteBuffer generate_nonce(std::size_t length) = 0;

    /**
     * Generate a random AES key, e.g. a session key for a request to a PKI authority
     * \return key or error, see SecurityModuleError for conditions
     */
    virtual expected<Aes128Key> generate_aes_key() = 0;

    /**
     * Encrypt a symmetric key for a recipient by ECIES with a fresh ephemeral key
     * \param recipient public encryption key of recipient
     * \param key symmetric key
     * \param info key derivation parameter, i.e. hash of recipient's certificate
     * \return encrypted key or error, see SecurityModuleError for conditions
     */
    virtual expected<EncryptedSymmetricKey> encrypt_key(
        const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info) = 0;

    /**
     * Encrypt by AES-CCM with a fresh nonce
     * \param key symmetric key
     * \param plaintext payload
     * \return ciphertext or error, see SecurityModuleError for conditions
     */
    virtual expected<AesCcmCiphertext> encrypt_aes_ccm(const Aes128Key& key, const ByteBuffer& plaintext) = 0;

    /**
     * Decrypt AES-CCM ciphertext
     * \param key symmetric key
     * \param ciphertext encrypted payload
     * \return payload or error, see SecurityModuleError for conditions
     */
    virtual expected<ByteBuffer> decrypt_aes_ccm(const Aes128Key& key, const AesCcmCiphertext& ciphertext) = 0;

    virtual ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) = 0;
};

} // namespace security
} // namespace vanetza
