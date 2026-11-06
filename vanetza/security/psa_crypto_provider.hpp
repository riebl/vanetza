#pragma once

#include <vanetza/security/crypto_provider.hpp>

namespace vanetza
{
namespace security
{

/**
 * CryptoProvider by the PSA Crypto API
 *
 * PSA imports uncompressed public keys only, thus Mbed TLS's PK module decompresses them,
 * i.e. this provider requires Mbed TLS (TF-PSA-Crypto or Mbed TLS 3.6) beyond the PSA Crypto API.
 */
class PsaCryptoProvider : public CryptoProvider
{
public:
    Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) override;
    Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) override;
    expected<bool> verify(const Sha256Hash&, const Signature&, const PublicKey&) override;
    expected<bool> verify(const Sha384Hash&, const Signature&, const PublicKey&) override;
    expected<AesCcmCiphertext> encrypt_aes_ccm(const Aes128Key&, const ByteBuffer& plaintext) override;
    expected<ByteBuffer> decrypt_aes_ccm(const Aes128Key&, const AesCcmCiphertext&) override;
    expected<Sha256Hmac> calculate_hmac_sha256(const byte_view_range& key, const byte_view_range& data) override;
};

} // namespace security
} // namespace vanetza
