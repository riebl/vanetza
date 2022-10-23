#ifndef BENCHMARK_CASES_SECURITY_BASE_HPP
#define BENCHMARK_CASES_SECURITY_BASE_HPP

#include "case.hpp"
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/trust_store.hpp>

class SecurityBaseCase : public Case
{
public:
    SecurityBaseCase();

    void prepare() override;

protected:
    vanetza::ManualRuntime runtime;
    vanetza::StoredPositionProvider positioning;
    std::unique_ptr<vanetza::security::Backend> crypto_backend;
    vanetza::security::v2::TrustStore trust_store;
    vanetza::security::v2::CertificateCache certificate_cache;
    vanetza::security::v2::NaiveCertificateProvider certificate_provider;
    vanetza::security::v2::DefaultCertificateValidator certificate_validator;
    vanetza::security::v2::DefaultSignHeaderPolicy sign_header_policy;
    vanetza::security::DelegatingSecurityEntity security_entity;

    std::unique_ptr<vanetza::security::SignService> create_sign_service();
    std::unique_ptr<vanetza::security::VerifyService> create_verify_service();
};

#endif /* BENCHMARK_CASES_SECURITY_BASE_HPP */
