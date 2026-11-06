#pragma once
#include <vanetza/security/crypto_provider.hpp>

namespace vanetza
{
namespace security
{

// forward declaration
class Backend;

/**
 * CryptoProvider hashing and verifying signatures by a Backend,
 * i.e. migration path for callers passing a Backend to code built on CryptoProvider.
 * AES-CCM and HMAC fail with std::errc::operation_not_supported.
 */
class BackendCryptoProvider : public CryptoProvider
{
public:
    /**
     * \param backend has to outlive this provider
     */
    explicit BackendCryptoProvider(Backend& backend);

    Sha256Hash calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length) override;
    Sha384Hash calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length) override;
    expected<bool> verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& key) override;
    expected<bool> verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& key) override;
    expected<AesCcmCiphertext> encrypt_aes_ccm(const Aes128Key& key, const ByteBuffer& plaintext) override;
    expected<ByteBuffer> decrypt_aes_ccm(const Aes128Key& key, const AesCcmCiphertext& ciphertext) override;
    expected<Sha256Hmac> calculate_hmac_sha256(const byte_view_range& key, const byte_view_range& data) override;

private:
    Backend& m_backend;
};

} // namespace security
} // namespace vanetza
