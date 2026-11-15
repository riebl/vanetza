#ifndef BENCHMARK_CASES_SECURITY_BASE_HPP
#define BENCHMARK_CASES_SECURITY_BASE_HPP

#include "case.hpp"
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_credential_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <memory>

class SecurityBaseCase : public Case
{
public:
    SecurityBaseCase();

    void prepare() override;

protected:
    vanetza::ManualRuntime runtime;
    vanetza::StoredPositionProvider positioning;
    std::unique_ptr<vanetza::security::CryptoProvider> crypto;
    std::unique_ptr<vanetza::security::SecurityModule> module;
    vanetza::security::v2::TrustStore trust_store;
    vanetza::security::v2::CertificateCache certificate_cache;
    vanetza::security::v2::NaiveCredentialProvider credentials;
    vanetza::security::v2::DefaultCertificateValidator certificate_validator;
    vanetza::security::v2::DefaultSignHeaderPolicy sign_header_policy;
    vanetza::security::DelegatingSecurityEntity security_entity;

    /**
     * Create provider of naive credentials whose certificates are issued
     * \return provider, std::runtime_error is thrown if issuing fails
     */
    std::unique_ptr<vanetza::security::v2::NaiveCredentialProvider> create_credentials();

    std::unique_ptr<vanetza::security::SignService> create_sign_service(vanetza::security::v2::CredentialProvider&);
    std::unique_ptr<vanetza::security::VerifyService> create_verify_service();
};

#endif /* BENCHMARK_CASES_SECURITY_BASE_HPP */
