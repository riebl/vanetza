#pragma once

#include <vanetza/common/byte_view.hpp>
#include <vanetza/common/expected.hpp>
#include <vanetza/security/aes.hpp>
#include <vanetza/security/encrypted_symmetric_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/sha.hpp>

namespace vanetza
{
namespace security
{

class CryptoProvider;

/**
 * Encrypt an AES-128 key by ECIES as specified by IEEE 1609.2
 * \param crypto crypto provider for key derivation and authentication tag
 * \param ephemeral_key sender's ephemeral public key
 * \param shared_secret ECDH shared secret of sender's ephemeral private key and recipient's public key
 * \param key AES-128 key
 * \param info key derivation parameter, i.e. hash of recipient's certificate
 * \return encrypted key or error, see SecurityModuleError for conditions
 */
expected<EncryptedSymmetricKey> encrypt_key(CryptoProvider& crypto, const PublicKey& ephemeral_key,
    const byte_view_range& shared_secret, const Aes128Key& key, const Sha256Hash& info);

} // namespace security
} // namespace vanetza
