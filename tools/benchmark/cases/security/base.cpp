#include "base.hpp"
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <stdexcept>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

std::unique_ptr<CryptoProvider> create_crypto_provider_or_throw()
{
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    if (!crypto) {
        throw std::runtime_error("benchmark requires a crypto provider");
    }
    return crypto;
}

std::unique_ptr<SecurityModule> create_security_module_or_throw()
{
    std::unique_ptr<SecurityModule> module = create_security_module();
    if (!module) {
        throw std::runtime_error("benchmark requires a security module");
    }
    return module;
}

} // namespace

SecurityBaseCase::SecurityBaseCase() :
    runtime(Clock::at(boost::posix_time::microsec_clock::universal_time())),
    crypto(create_crypto_provider_or_throw()),
    module(create_security_module_or_throw()),
    trust_store(*crypto),
    certificate_cache(runtime, *crypto),
    credentials(*module, *crypto),
    certificate_validator(*crypto, certificate_cache, trust_store),
    sign_header_policy(runtime, *crypto, positioning),
    security_entity(create_sign_service(credentials), create_verify_service())
{
    const std::error_code error = credentials.issue_certificates(runtime.now());
    if (error) {
        throw std::runtime_error("cannot issue naive certificates: " + error.message());
    }
}

void SecurityBaseCase::prepare()
{
    PositionFix position;
    position.latitude = 49.014420 * units::degree;
    position.longitude = 8.404417 * units::degree;
    position.confidence.semi_major = 25.0 * units::si::meter;
    position.confidence.semi_minor = 25.0 * units::si::meter;
    assert(position.confidence);

    positioning.position_fix(position);
}

std::unique_ptr<v2::NaiveCredentialProvider> SecurityBaseCase::create_credentials()
{
    auto provider = std::make_unique<v2::NaiveCredentialProvider>(*module, *crypto);
    const std::error_code error = provider->issue_certificates(runtime.now());
    if (error) {
        throw std::runtime_error("cannot issue naive certificates: " + error.message());
    }
    return provider;
}

std::unique_ptr<SignService> SecurityBaseCase::create_sign_service(v2::CredentialProvider& credential_provider)
{
    return std::unique_ptr<SignService> {
        new v2::SecurityModuleSignService(*module, *crypto, credential_provider, sign_header_policy)
    };
}

std::unique_ptr<VerifyService> SecurityBaseCase::create_verify_service()
{
    std::unique_ptr<CryptoProviderVerifyService> verify_service {
        new CryptoProviderVerifyService(runtime, *crypto, positioning) };
    verify_service->use_certificate_cache(&certificate_cache);
    verify_service->use_certificate_validator(&certificate_validator);
    verify_service->use_sign_header_policy(&sign_header_policy);
    return verify_service;
}
