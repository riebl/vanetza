#pragma once

#include <vanetza/security/crypto_provider.hpp>

namespace vanetza
{
namespace security
{

class CryptoppCryptoProvider : public CryptoProvider
{
public:
    Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) override;
    Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) override;
    expected<bool> verify(const Sha256Hash&, const Signature&, const PublicKey&) override;
    expected<bool> verify(const Sha384Hash&, const Signature&, const PublicKey&) override;
    expected<AesCcmCiphertext> encrypt_aes_ccm(const Aes128Key&, const ByteBuffer& plaintext) override;
    expected<ByteBuffer> decrypt_aes_ccm(const Aes128Key&, const AesCcmCiphertext&) override;
    expected<Sha256Hmac> calculate_hmac_sha256(const byte_view_range& key, const byte_view_range& data) override;

private:
    expected<bool> verify(const std::uint8_t* digest, std::size_t length, const Signature&, const PublicKey&);
};

} // namespace security
} // namespace vanetza
