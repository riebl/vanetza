#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/signature.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class SecurityModule
{
public:
    class EciesContext
    {
    public:
        virtual ~EciesContext() = default;
        virtual PublicKey ephemeral_public_key() const = 0;
        virtual PublicKey recipient_public_key() const = 0;
        virtual ByteBuffer shared_secret() const = 0;
        virtual ByteBuffer encrypted_key() const = 0;
        virtual ByteBuffer authentication_tag() const = 0;
        virtual ByteBuffer nonce() const = 0;
        virtual void nonce(const ByteBuffer&) = 0;

        virtual ByteBuffer encrypt(const ByteBuffer& plaintext) = 0;
        virtual ByteBuffer decrypt(const std::uint8_t* buffer, std::size_t length) = 0;
    };

    virtual ~SecurityModule() = default;
    virtual Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) = 0;
    virtual Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) = 0;
    virtual bool verify(const Sha256Hash&, const Signature&, const PublicKey&) = 0;
    virtual bool verify(const Sha384Hash&, const Signature&, const PublicKey&) = 0;

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
    virtual std::unique_ptr<EciesContext> create_ecies_context(const PublicKey& receiver, const Sha256Hash& info) = 0;
    virtual ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) = 0;
};

} // namespace security
} // namespace vanetza
