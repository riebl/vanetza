#pragma once

#include <vanetza/security/security_module.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

class CredentialStorage;

class OpenSslSecurityModule : public SecurityModule
{
public:
    /**
     * Create module without credential storage, its key references are self-contained
     */
    OpenSslSecurityModule() = default;

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
    std::shared_ptr<CredentialStorage> m_credential_storage;
};

} // namespace security
} // namespace vanetza
