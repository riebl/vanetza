#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_crypto_provider.hpp>
#include <algorithm>
#include <system_error>

namespace vanetza
{
namespace security
{

namespace
{

template<typename Hash>
Hash calculate_hash(Backend& backend, HashAlgorithm algo, const std::uint8_t* buffer, std::size_t length)
{
    const ByteBuffer digest = backend.calculate_hash(algo, ByteBuffer(buffer, buffer + length));
    Hash hash {};
    std::copy_n(digest.begin(), std::min(digest.size(), hash.octets.size()), hash.octets.begin());
    return hash;
}

} // namespace

BackendCryptoProvider::BackendCryptoProvider(Backend& backend) : m_backend(backend)
{
}

Sha256Hash BackendCryptoProvider::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    return calculate_hash<Sha256Hash>(m_backend, HashAlgorithm::SHA256, buffer, length);
}

Sha384Hash BackendCryptoProvider::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    return calculate_hash<Sha384Hash>(m_backend, HashAlgorithm::SHA384, buffer, length);
}

expected<bool> BackendCryptoProvider::verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& key)
{
    return m_backend.verify_digest(key, ByteBuffer(digest.octets.begin(), digest.octets.end()), signature);
}

expected<bool> BackendCryptoProvider::verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& key)
{
    return m_backend.verify_digest(key, ByteBuffer(digest.octets.begin(), digest.octets.end()), signature);
}

expected<AesCcmCiphertext> BackendCryptoProvider::encrypt_aes_ccm(const Aes128Key&, const ByteBuffer&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<ByteBuffer> BackendCryptoProvider::decrypt_aes_ccm(const Aes128Key&, const AesCcmCiphertext&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<Sha256Hmac> BackendCryptoProvider::calculate_hmac_sha256(const byte_view_range&, const byte_view_range&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

} // namespace security
} // namespace vanetza
