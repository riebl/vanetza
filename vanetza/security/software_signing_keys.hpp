#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <memory>
#include <system_error>

namespace vanetza
{
namespace security
{

class CredentialStorage;

/**
 * Signing keys of a SecurityModule held in software, i.e. key references contain the private keys
 *
 * References are the key type followed by the big-endian private scalar of key_length() octets.
 * An optional credential storage keeps created keys, so find_key() can look them up by public key.
 * Security modules inherit privately and implement the cryptographic hooks.
 */
class SoftwareSigningKeys
{
protected:
    explicit SoftwareSigningKeys(std::shared_ptr<CredentialStorage> storage);
    ~SoftwareSigningKeys() = default;

    // implementations of SecurityModule's signing key operations
    expected<KeyReference> create_key(KeyType);
    expected<KeyReference> find_key(const PublicKey&);
    expected<PublicKey> public_key_of(const KeyReference&);
    expected<Signature> sign_with(const ByteBuffer& digest, const KeyReference&);
    bool discard(const KeyReference&);

    // implementation of SigningKeyImport
    expected<KeyReference> import_key(const PrivateKey&);

private:
    std::error_code store_credential(const PublicKey&, const PrivateKey&);

    /**
     * Generate a private key
     * \param type supported key type
     * \return private key or error
     */
    virtual expected<PrivateKey> generate_private_key(KeyType type) = 0;

    /**
     * Derive compressed public key of a private key
     * \param key private key of supported type and length
     * \return public key or error, InvalidKeyReference for a scalar out of range
     */
    virtual expected<PublicKey> derive_public_key(const PrivateKey& key) = 0;

    /**
     * Sign a digest by ECDSA
     * \param digest hash value of data
     * \param key private key of supported type and length
     * \return signature or error, InvalidKeyReference for a scalar out of range
     */
    virtual expected<Signature> sign_digest(const ByteBuffer& digest, const PrivateKey& key) = 0;

    std::shared_ptr<CredentialStorage> m_credential_storage;
};

} // namespace security
} // namespace vanetza
