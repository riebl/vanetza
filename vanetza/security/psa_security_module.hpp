#pragma once

#include <vanetza/security/security_module.hpp>
#include <vanetza/security/signing_key_import.hpp>

namespace vanetza
{
namespace security
{

/**
 * SecurityModule keeping its signing keys as persistent keys of the PSA Crypto API
 *
 * A key reference is the 4-octet big-endian identifier of its persistent key. The identifier derives from the public
 * key, i.e. 30 bits of SHA-256 over its canonical_hexstring, thus keys are found by their public keys without
 * further storage. Like PsaCryptoProvider, this module requires Mbed TLS beyond the PSA Crypto API for decompressing
 * public keys. Imported keys are stored like created keys.
 */
class PsaSecurityModule : public SecurityModule, public SigningKeyImport
{
public:
    expected<KeyReference> create_signing_key(KeyType) override;
    expected<KeyReference> find_signing_key(const PublicKey&) override;
    expected<PublicKey> public_key(const KeyReference&) override;
    expected<Signature> sign(const ByteBuffer& digest, const KeyReference&) override;
    bool discard_key(const KeyReference&) override;
    expected<KeyReference> import_signing_key(const PrivateKey&) override;

    expected<Aes128Key> generate_aes_key() override;
    expected<HmacKey> generate_hmac_key() override;
    expected<EncryptedSymmetricKey> encrypt_key(
        const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info) override;
};

} // namespace security
} // namespace vanetza
