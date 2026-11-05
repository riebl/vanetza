#include <vanetza/security/security_module.hpp>
#if defined VANETZA_WITH_OPENSSL
#   include <vanetza/security/openssl_security_module.hpp>
#endif

namespace vanetza
{
namespace security
{

namespace
{

Factory<SecurityModule> build_builtin_security_modules()
{
    Factory<SecurityModule> factory;
#if defined VANETZA_WITH_OPENSSL
    factory.add("OpenSSL", []() { return std::unique_ptr<SecurityModule> { new OpenSslSecurityModule() }; });
    factory.configure_default("OpenSSL");
#endif
    return factory;
}

} // namespace

const Factory<SecurityModule>& builtin_security_modules()
{
    static const Factory<SecurityModule> factory = build_builtin_security_modules();
    return factory;
}

std::unique_ptr<SecurityModule> create_security_module(const std::string& name, const Factory<SecurityModule>& factory)
{
    if (name == "default") {
        return factory.create();
    } else {
        return factory.create(name);
    }
}

} // namespace security
} // namespace vanetza
