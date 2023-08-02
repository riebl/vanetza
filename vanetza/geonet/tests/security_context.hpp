#ifndef SECURITY_CONTEXT_HPP_FEYZW1RS
#define SECURITY_CONTEXT_HPP_FEYZW1RS

#include <vanetza/common/runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/straight_verify_service.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/trust_store.hpp>

namespace vanetza
{

class SecurityContext
{
public:
    SecurityContext(Runtime& rt) :
        backend(security::create_backend("default")),
        certificate_provider(new security::v2::NaiveCertificateProvider(rt)),
        cert_cache(rt),
        certificate_validator(new security::v2::DefaultCertificateValidator(*backend, cert_cache, trust_store)),
        sign_header_policy(rt, position_provider),
        security(
            std::unique_ptr<security::SignService> {
                new security::v2::StraightSignService(*certificate_provider, *backend, sign_header_policy) },
            std::unique_ptr<security::VerifyService> {
                new security::StraightVerifyService(rt, *certificate_provider, *certificate_validator, *backend, cert_cache, sign_header_policy, position_provider) }
        )
    {
        trust_store.insert(certificate_provider->root_certificate());
        for (auto cert : certificate_provider->own_chain()) {
            cert_cache.insert(cert);
        }
    }

    security::SecurityEntity& entity()
    {
        return security;
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

private:
    StoredPositionProvider position_provider;
    std::unique_ptr<security::Backend> backend;
    std::unique_ptr<security::v2::NaiveCertificateProvider> certificate_provider;
    std::vector<security::v2::Certificate> roots;
    security::v2::TrustStore trust_store;
    security::v2::CertificateCache cert_cache;
    std::unique_ptr<security::v2::CertificateValidator> certificate_validator;
    security::v2::DefaultSignHeaderPolicy sign_header_policy;
    security::DelegatingSecurityEntity security;
};

} // namespace vanetza

#endif /* SECURITY_CONTEXT_HPP_FEYZW1RS */
