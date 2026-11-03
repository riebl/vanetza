#pragma once

#include "keys.hpp"
#include "security_module.hpp"
#include "sha.hpp"
#include <vanetza/security/aes.hpp>

namespace vanetza
{
namespace pki
{

class CredentialStorage;

class OpenSslSecurityModule : public SecurityModule
{
public:
    explicit OpenSslSecurityModule(std::shared_ptr<CredentialStorage>);

    Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) override;
    Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) override;
    bool verify(const Sha256Hash&, const Signature&, const PublicKey&) override;
    bool verify(const Sha384Hash&, const Signature&, const PublicKey&) override;
    ByteBuffer generate_nonce(std::size_t length) override;
    std::unique_ptr<EciesContext> create_ecies_context(const PublicKey& receiver, const Sha256Hash& info) override;
    expected<security::Aes128Key> generate_aes_key() override;
    expected<EncryptedSymmetricKey> encrypt_key(const PublicKey& recipient, const security::Aes128Key& key, const Sha256Hash& info) override;
    expected<AesCcmCiphertext> encrypt_aes_ccm(const security::Aes128Key&, const ByteBuffer& plaintext) override;
    expected<ByteBuffer> decrypt_aes_ccm(const security::Aes128Key&, const AesCcmCiphertext&) override;
    ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data) override;

    expected<KeyReference> create_signing_key(KeyType) override;
    expected<KeyReference> find_signing_key(const PublicKey&) override;
    expected<PublicKey> public_key(const KeyReference&) override;
    expected<Signature> sign(const ByteBuffer& digest, const KeyReference&) override;
    bool discard_key(const KeyReference&) override;

private:
    bool verify(const uint8_t* digest, std::size_t dlen, const Signature&, const PublicKey&);

    std::shared_ptr<CredentialStorage> m_credential_storage;
};

} // namespace pki
} // namespace vanetza
