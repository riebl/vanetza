#include <vanetza/security/tests/implementations.hpp>
#if defined VANETZA_WITH_CRYPTOPP
#   include <vanetza/security/cryptopp_security_module.hpp>
#endif
#if defined VANETZA_WITH_OPENSSL
#   include <vanetza/security/openssl_security_module.hpp>
#endif
#include <algorithm>

namespace vanetza
{
namespace security
{

std::vector<std::string> builtin_crypto_provider_names()
{
    std::vector<std::string> providers;
#if defined VANETZA_WITH_CRYPTOPP
    providers.emplace_back("Crypto++");
#endif
#if defined VANETZA_WITH_OPENSSL
    providers.emplace_back("OpenSSL");
#endif
#if defined VANETZA_WITH_PSA
    providers.emplace_back("PSA");
#endif
    return providers;
}

std::vector<std::string> builtin_security_module_names()
{
    std::vector<std::string> modules;
#if defined VANETZA_WITH_CRYPTOPP
    modules.emplace_back("Crypto++");
#endif
#if defined VANETZA_WITH_OPENSSL
    modules.emplace_back("OpenSSL");
#endif
#if defined VANETZA_WITH_PSA
    modules.emplace_back("PSA");
#endif
    return modules;
}

std::vector<std::string> software_security_module_names()
{
    std::vector<std::string> modules;
#if defined VANETZA_WITH_CRYPTOPP
    modules.emplace_back("Crypto++");
#endif
#if defined VANETZA_WITH_OPENSSL
    modules.emplace_back("OpenSSL");
#endif
    return modules;
}

std::unique_ptr<SecurityModule> create_software_security_module(
    const std::string& name, std::shared_ptr<CredentialStorage> storage)
{
#if defined VANETZA_WITH_CRYPTOPP
    if (name == "Crypto++") {
        return std::make_unique<CryptoppSecurityModule>(storage);
    }
#endif
#if defined VANETZA_WITH_OPENSSL
    if (name == "OpenSSL") {
        return std::make_unique<OpenSslSecurityModule>(storage);
    }
#endif
    return nullptr;
}

std::string implementation_test_name(const ::testing::TestParamInfo<std::string>& info)
{
    std::string name = info.param;
    std::replace(name.begin(), name.end(), '+', 'P');
    return name;
}

} // namespace security
} // namespace vanetza
