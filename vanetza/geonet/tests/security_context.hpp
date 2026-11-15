#ifndef SECURITY_CONTEXT_HPP_FEYZW1RS
#define SECURITY_CONTEXT_HPP_FEYZW1RS

#include <vanetza/common/runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_credential_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/location_checker.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <memory>
#include <stdexcept>
#include <string>

namespace vanetza
{

class SecurityContext
{
public:
    explicit SecurityContext(Runtime& rt) :
        crypto(require(security::create_crypto_provider(), "crypto provider")),
        module(require(security::create_security_module(), "security module")),
        credentials(*module, *crypto),
        trust_store(*crypto),
        cert_cache(rt, *crypto),
        certificate_validator(*crypto, cert_cache, trust_store),
        sign_header_policy(rt, *crypto, position_provider),
        cert_cache_v3(*crypto),
        sign_header_policy_v3(rt, *crypto, position_provider, cert_cache_v3),
        certificate_validator_v3(*crypto),
        security(build_sign_service(), build_verify_service(rt))
    {
        const std::error_code error = credentials.issue_certificates(rt.now());
        if (error) {
            throw std::runtime_error("cannot issue naive certificates: " + error.message());
        }
        trust(*this);

        // wire up v3 certificate validator
        certificate_validator_v3.use_runtime(&rt);
        certificate_validator_v3.use_position_provider(&position_provider);
        certificate_validator_v3.use_location_checker(&location_checker);
    }

    security::SecurityEntity& entity()
    {
        return security;
    }

    /**
     * Trust certificates issued by the naive credentials of a context
     */
    void trust(const SecurityContext& other)
    {
        trust_store.insert(*other.credentials.root_certificate());
        cert_cache.insert(*other.credentials.aa_certificate());
    }

    void set_accurate_position(units::GeoAngle latitude, units::GeoAngle longitude)
    {
        PositionFix position_fix;
        position_fix.latitude = latitude;
        position_fix.longitude = longitude;
        position_fix.confidence.semi_major = 25.0 * units::si::meter;
        position_fix.confidence.semi_minor = 25.0 * units::si::meter;
        assert(position_fix.confidence);
        position_provider.position_fix(position_fix);
    }

    security::v3::CertificateCache& certificate_cache_v3()
    {
        return cert_cache_v3;
    }

private:
    template<typename T>
    static std::unique_ptr<T> require(std::unique_ptr<T> implementation, const std::string& what)
    {
        if (!implementation) {
            throw std::runtime_error("secured geonet tests require a " + what);
        }
        return implementation;
    }

    std::unique_ptr<security::VerifyService> build_verify_service(Runtime& rt)
    {
        std::unique_ptr<security::CryptoProviderVerifyService> service {
            new security::CryptoProviderVerifyService(rt, *crypto, position_provider)
        };
        service->use_certificate_cache(&cert_cache);
        service->use_certificate_validator(&certificate_validator);
        service->use_sign_header_policy(&sign_header_policy);

        service->use_certificate_cache(&cert_cache_v3);
        service->use_certificate_validator(&certificate_validator_v3);
        service->use_sign_header_policy(&sign_header_policy_v3);
        return service;
    }

    std::unique_ptr<security::SignService> build_sign_service()
    {
        return std::unique_ptr<security::SignService> {
            new security::v2::SecurityModuleSignService(*module, *crypto, credentials, sign_header_policy)
        };
    }

    StoredPositionProvider position_provider;
    security::v3::DefaultLocationChecker location_checker;
    std::unique_ptr<security::CryptoProvider> crypto;
    std::unique_ptr<security::SecurityModule> module;

    security::v2::NaiveCredentialProvider credentials;
    security::v2::TrustStore trust_store;
    security::v2::CertificateCache cert_cache;
    security::v2::DefaultCertificateValidator certificate_validator;
    security::v2::DefaultSignHeaderPolicy sign_header_policy;

    security::v3::CertificateCache cert_cache_v3;
    security::v3::DefaultSignHeaderPolicy sign_header_policy_v3;
    security::v3::DefaultCertificateValidator certificate_validator_v3;
    
    security::DelegatingSecurityEntity security;
};

} // namespace vanetza

#endif /* SECURITY_CONTEXT_HPP_FEYZW1RS */
