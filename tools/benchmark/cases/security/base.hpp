#ifndef BENCHMARK_CASES_SECURITY_BASE_HPP
#define BENCHMARK_CASES_SECURITY_BASE_HPP

#include "case.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/verify_service.hpp>

class SecurityBaseCase : public Case
{
public:
    SecurityBaseCase();

    void prepare() override;

protected:
    vanetza::Runtime runtime;
    vanetza::StoredPositionProvider positioning;
    std::unique_ptr<vanetza::security::Backend> crypto_backend;
    vanetza::security::TrustStore trust_store;
    vanetza::security::CertificateCache certificate_cache;
    vanetza::security::NaiveCertificateProvider certificate_provider;
    vanetza::security::DefaultCertificateValidator certificate_validator;
    vanetza::security::SignHeaderPolicy sign_header_policy;
    vanetza::security::SignService sign_service;
    vanetza::security::VerifyService verify_service;
    vanetza::security::SecurityEntity security_entity;
};

#endif /* BENCHMARK_CASES_SECURITY_BASE_HPP */
