#pragma once

#include <vanetza/security/security_module.hpp>
#include <vanetza/security/software_signing_keys.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class CredentialStorage;

class OpenSslSecurityModule : public SecurityModule, private SoftwareSigningKeys
{
public:
    /**
     * Create module without credential storage, its key references are self-contained
     */
    OpenSslSecurityModule();

    /**
     * Create module storing its created keys permanently
     * \param storage credential storage
     */
    explicit OpenSslSecurityModule(std::shared_ptr<CredentialStorage> storage);

    expected<Aes128Key> generate_aes_key() override;
    expected<HmacKey> generate_hmac_key() override;
    expected<EncryptedSymmetricKey> encrypt_key(
        const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info) override;

    expected<KeyReference> create_signing_key(KeyType) override;
    expected<KeyReference> find_signing_key(const PublicKey&) override;
    expected<PublicKey> public_key(const KeyReference&) override;
    expected<Signature> sign(const ByteBuffer& digest, const KeyReference&) override;
    bool discard_key(const KeyReference&) override;

private:
    expected<PrivateKey> generate_private_key(KeyType) override;
    expected<PublicKey> derive_public_key(const PrivateKey&) override;
    expected<Signature> sign_digest(const ByteBuffer& digest, const PrivateKey&) override;
};

} // namespace security
} // namespace vanetza
