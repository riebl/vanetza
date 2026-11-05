#include <vanetza/security/crypto_provider.hpp>
#if defined VANETZA_WITH_OPENSSL
#   include <vanetza/security/openssl_crypto_provider.hpp>
#endif

namespace vanetza
{
namespace security
{

namespace
{

Factory<CryptoProvider> build_builtin_crypto_providers()
{
    Factory<CryptoProvider> factory;
#if defined VANETZA_WITH_OPENSSL
    factory.add("OpenSSL", []() { return std::unique_ptr<CryptoProvider> { new OpenSslCryptoProvider() }; });
    factory.configure_default("OpenSSL");
#endif
    return factory;
}

} // namespace

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
