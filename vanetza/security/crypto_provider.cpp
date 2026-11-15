#include <vanetza/security/crypto_provider.hpp>
#if defined VANETZA_WITH_CRYPTOPP
#   include <vanetza/security/cryptopp_crypto_provider.hpp>
#endif
#if defined VANETZA_WITH_OPENSSL
#   include <vanetza/security/openssl_crypto_provider.hpp>
#endif
#if defined VANETZA_WITH_PSA
#   include <vanetza/security/psa_crypto_provider.hpp>
#endif
#include <algorithm>

namespace vanetza
{
namespace security
{

namespace
{

// verifies signature of a hash calculated by algorithm of given digest type
template<typename Digest>
expected<bool> verify_digest(
    CryptoProvider& crypto, const ByteBuffer& hash, const Signature& signature, const PublicKey& key)
{
    Digest digest;
    if (hash.size() != digest.octets.size()) {
        return make_error_code(SecurityModuleError::InvalidHashLength);
    }
    std::copy(hash.begin(), hash.end(), digest.octets.begin());
    return crypto.verify(digest, signature, key);
}

Factory<CryptoProvider> build_builtin_crypto_providers()
{
    Factory<CryptoProvider> factory;
    // Crypto++ is the least preferred provider
#if defined VANETZA_WITH_CRYPTOPP
    factory.add("Crypto++", []() { return std::unique_ptr<CryptoProvider> { new CryptoppCryptoProvider() }; });
    factory.configure_default("Crypto++");
#endif
#if defined VANETZA_WITH_PSA
    factory.add("PSA", []() { return std::unique_ptr<CryptoProvider> { new PsaCryptoProvider() }; });
    factory.configure_default("PSA");
#endif
    // OpenSSL is preferred over PSA if both are available
#if defined VANETZA_WITH_OPENSSL
    factory.add("OpenSSL", []() { return std::unique_ptr<CryptoProvider> { new OpenSslCryptoProvider() }; });
    factory.configure_default("OpenSSL");
#endif
    return factory;
}

} // namespace

ByteBuffer calculate_hash(CryptoProvider& crypto, HashAlgorithm algo, const ByteBuffer& data)
{
    switch (algo) {
        case HashAlgorithm::SHA256: {
            const Sha256Hash hash = crypto.calculate_sha256_hash(data.data(), data.size());
            return ByteBuffer(hash.octets.begin(), hash.octets.end());
        }
        case HashAlgorithm::SHA384: {
            const Sha384Hash hash = crypto.calculate_sha384_hash(data.data(), data.size());
            return ByteBuffer(hash.octets.begin(), hash.octets.end());
        }
        default:
            return ByteBuffer {};
    }
}

expected<bool> verify_hash(CryptoProvider& crypto, HashAlgorithm algo, const ByteBuffer& hash,
    const Signature& signature, const PublicKey& key)
{
    switch (algo) {
        case HashAlgorithm::SHA256:
            return verify_digest<Sha256Hash>(crypto, hash, signature, key);
        case HashAlgorithm::SHA384:
            return verify_digest<Sha384Hash>(crypto, hash, signature, key);
        default:
            return make_error_code(SecurityModuleError::UnsupportedHashAlgorithm);
    }
}

const Factory<CryptoProvider>& builtin_crypto_providers()
{
    static const Factory<CryptoProvider> factory = build_builtin_crypto_providers();
    return factory;
}

std::unique_ptr<CryptoProvider> create_crypto_provider(const std::string& name, const Factory<CryptoProvider>& factory)
{
    if (name == "default") {
        return factory.create();
    } else {
        return factory.create(name);
    }
}

} // namespace security
} // namespace vanetza
