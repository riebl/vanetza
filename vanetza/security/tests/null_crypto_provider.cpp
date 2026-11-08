#include <vanetza/security/tests/null_crypto_provider.hpp>
#include <system_error>

namespace vanetza
{
namespace security
{

NullCryptoProvider& NullCryptoProvider::instance()
{
    static NullCryptoProvider provider;
    return provider;
}

Sha256Hash NullCryptoProvider::calculate_sha256_hash(const std::uint8_t*, std::size_t)
{
    return Sha256Hash {};
}

Sha384Hash NullCryptoProvider::calculate_sha384_hash(const std::uint8_t*, std::size_t)
{
    return Sha384Hash {};
}

expected<bool> NullCryptoProvider::verify(const Sha256Hash&, const Signature&, const PublicKey&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<bool> NullCryptoProvider::verify(const Sha384Hash&, const Signature&, const PublicKey&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<AesCcmCiphertext> NullCryptoProvider::encrypt_aes_ccm(const Aes128Key&, const ByteBuffer&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<ByteBuffer> NullCryptoProvider::decrypt_aes_ccm(const Aes128Key&, const AesCcmCiphertext&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

expected<Sha256Hmac> NullCryptoProvider::calculate_hmac_sha256(const byte_view_range&, const byte_view_range&)
{
    return std::make_error_code(std::errc::operation_not_supported);
}

} // namespace security
} // namespace vanetza
