#ifndef SECURITY_CONTEXT_HPP_FEYZW1RS
#define SECURITY_CONTEXT_HPP_FEYZW1RS

#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/trust_store.hpp>

namespace vanetza
{

class SecurityContext
{
public:
    SecurityContext(Runtime& rt) :
        backend(security::create_backend("default")),
        certificate_provider(new security::NaiveCertificateProvider(rt.now())),
        roots({ certificate_provider->root_certificate() }),
        trust_store(roots),
        cert_cache(rt.now()),
        certificate_validator(new security::DefaultCertificateValidator(rt.now(), trust_store, cert_cache)),
        sign_header_policy(rt.now()),
        security(
            straight_sign_service(*certificate_provider, *backend, sign_header_policy),
            straight_verify_service(rt, *certificate_provider, *certificate_validator, *backend, cert_cache, sign_header_policy))
    {
        for (auto cert : certificate_provider->own_chain()) {
            cert_cache.put(cert);
        }
    }

    security::SecurityEntity& entity()
    {
        return security;
    }

private:
    std::unique_ptr<security::Backend> backend;
    std::unique_ptr<security::NaiveCertificateProvider> certificate_provider;
    std::vector<security::Certificate> roots;
    security::TrustStore trust_store;
    security::CertificateCache cert_cache;
    std::unique_ptr<security::CertificateValidator> certificate_validator;
    security::SignHeaderPolicy sign_header_policy;
    security::SecurityEntity security;
};

} // namespace vanetza

#endif /* SECURITY_CONTEXT_HPP_FEYZW1RS */
