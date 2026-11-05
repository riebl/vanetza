#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_view.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/common/factory.hpp>
#include <vanetza/security/aes.hpp>
#include <vanetza/security/hmac.hpp>
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

/**
 * Cryptographic operations of the station not involving secrets guarded by its SecurityModule,
 * i.e. the station's own signature verification and AES (C2C-CC Protection Profile Vehicle C-ITS Station, FCS_COP.1)
 */
class CryptoProvider
{
public:
    virtual ~CryptoProvider() = default;
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

    /**
     * Calculate HMAC-SHA256 (RFC 2104), e.g. for keyTag of an authorization request (ETSI TS 102 941 §6.2.3.3.1)
     * \param key HMAC key of any length
     * \param data authenticated data
     * \return untruncated HMAC or error, see SecurityModuleError for conditions
     */
    virtual expected<Sha256Hmac> calculate_hmac_sha256(const byte_view_range& key, const byte_view_range& data) = 0;
};

/**
 * \brief get factory containing builtin crypto provider implementations
 *
 * Included set of providers depends on CMake build configuration, it may be empty.
 * \return factory
 */
const Factory<CryptoProvider>& builtin_crypto_providers();

/**
 * \brief create a crypto provider instance
 *
 * Name "default" selects the provider preferred by this build.
 * \param name identifying name of provider implementation
 * \param factory build provider registered by name from this factory
 * \return provider instance or nullptr if unavailable
 */
std::unique_ptr<CryptoProvider> create_crypto_provider(
    const std::string& name = "default", const Factory<CryptoProvider>& factory = builtin_crypto_providers());

} // namespace security
} // namespace vanetza
