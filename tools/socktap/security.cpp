#include "security.hpp"
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/straight_verify_service.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include "vanetza/security/v2/certificate_provider.hpp"
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/static_certificate_provider.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/static_certificate_provider.hpp>

#include <stdexcept>

using namespace vanetza;
namespace po = boost::program_options;

class SecurityContextV2 : public security::SecurityEntity
{
public:
    SecurityContextV2(const Runtime& runtime, PositionProvider& positioning) :
        runtime(runtime), positioning(positioning),
        backend(security::create_backend("default")),
        sign_header_policy(runtime, positioning),
        cert_cache(runtime),
        cert_validator(*backend, cert_cache, trust_store)
    {
    }

    security::EncapConfirm encapsulate_packet(security::EncapRequest&& request) override
    {
        if (!entity) {
            throw std::runtime_error("security entity is not ready");
        }
        return entity->encapsulate_packet(std::move(request));
    }

    security::DecapConfirm decapsulate_packet(security::DecapRequest&& request) override
    {
        if (!entity) {
            throw std::runtime_error("security entity is not ready");
        }
        return entity->decapsulate_packet(std::move(request));
    }

    void build_entity()
    {
        if (!cert_provider) {
            throw std::runtime_error("certificate provider is missing");
        }
        std::unique_ptr<security::SignService> sign_service { new
            security::v2::StraightSignService(*cert_provider, *backend, sign_header_policy) };
        std::unique_ptr<security::StraightVerifyService> verify_service { new
            security::StraightVerifyService(runtime, *backend, positioning) };
        verify_service->use_certificate_provider(cert_provider.get());
        verify_service->use_certificate_cache(&cert_cache);
        verify_service->use_certitifcate_validator(&cert_validator);
        verify_service->use_sign_header_policy(&sign_header_policy);
        entity.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    }

    const Runtime& runtime;
    PositionProvider& positioning;
    std::unique_ptr<security::Backend> backend;
    std::unique_ptr<security::SecurityEntity> entity;
    std::unique_ptr<security::v2::CertificateProvider> cert_provider;
    security::v2::DefaultSignHeaderPolicy sign_header_policy;
    security::v2::TrustStore trust_store;
    security::v2::CertificateCache cert_cache;
    security::v2::DefaultCertificateValidator cert_validator;
};

class SecurityContextV3 : public security::SecurityEntity
{
public:
    SecurityContextV3(const Runtime& runtime, PositionProvider& positioning) :
        runtime(runtime), positioning(positioning),
        backend(security::create_backend("default")),
        sign_header_policy(runtime, positioning),
        cert_cache()
    {
    }

    security::EncapConfirm encapsulate_packet(security::EncapRequest&& request) override
    {
        if (!entity) {
            throw std::runtime_error("security entity is not ready");
        }
        return entity->encapsulate_packet(std::move(request));
    }

    security::DecapConfirm decapsulate_packet(security::DecapRequest&& request) override
    {
        if (!entity) {
            throw std::runtime_error("security entity is not ready");
        }
        return entity->decapsulate_packet(std::move(request));
    }

    void build_entity()
    {
        if (!cert_provider) {
            throw std::runtime_error("certificate provider is missing");
        }
        std::unique_ptr<security::SignService> sign_service { new 
            security::v3::StraightSignService(*cert_provider, *backend, sign_header_policy) };
        std::unique_ptr<security::StraightVerifyService> verify_service { new
            security::StraightVerifyService(runtime, *backend, positioning) };
        verify_service->use_certificate_cache(&cert_cache);
        entity.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    }

    const Runtime& runtime;
    PositionProvider& positioning;
    std::unique_ptr<security::Backend> backend;
    std::unique_ptr<security::SecurityEntity> entity;
    std::unique_ptr<security::v3::CertificateProvider> cert_provider;
    security::v3::DefaultSignHeaderPolicy sign_header_policy;
    security::v3::CertificateCache cert_cache;
};

std::unique_ptr<security::SecurityEntity>
create_dummy_v2_security_entity(const Runtime& runtime)
{
    std::unique_ptr<security::SignService> sign_service { new security::v2::DummySignService { runtime, nullptr } };
    std::unique_ptr<security::VerifyService> verify_service { new security::DummyVerifyService {
        security::VerificationReport::Success, security::CertificateValidity::valid() } };
    return std::make_unique<security::DelegatingSecurityEntity>(std::move(sign_service), std::move(verify_service));
}

std::unique_ptr<security::SecurityEntity>
create_dummy_v3_security_entity(const Runtime& runtime)
{
    std::unique_ptr<security::SignService> sign_service { new security::v3::DummySignService { runtime } };
    std::unique_ptr<security::VerifyService> verify_service { new security::DummyVerifyService {
        security::VerificationReport::Success, security::CertificateValidity::valid() } };
    return std::make_unique<security::DelegatingSecurityEntity>(std::move(sign_service), std::move(verify_service));
}

std::unique_ptr<security::v2::CertificateProvider>
load_v2_certificates(const std::string& cert_path, const std::string& cert_key_path, const std::vector<std::string> cert_chain_path, security::v2::CertificateCache& cert_cache)
{
    auto authorization_ticket = security::v2::load_certificate_from_file(cert_path);
    auto authorization_ticket_key = security::v2::load_private_key_from_file(cert_key_path);

    std::list<security::v2::Certificate> chain;
    for (auto& chain_path : cert_chain_path) {
        auto chain_certificate = security::v2::load_certificate_from_file(chain_path);
        chain.push_back(chain_certificate);
        cert_cache.insert(chain_certificate);
    }

    return std::make_unique<security::v2::StaticCertificateProvider>(authorization_ticket, authorization_ticket_key.private_key, chain);
}

std::unique_ptr<security::v3::CertificateProvider>
load_v3_certificates(const std::string& cert_path, const std::string& cert_key_path, const std::vector<std::string> cert_chain_path, security::v3::CertificateCache& cert_cache)
{
    auto authorization_ticket = security::v3::load_certificate_from_file(cert_path);
    auto authorization_ticket_key = security::v3::load_private_key_from_file(cert_key_path);

    std::list<security::v3::Certificate> chain;
    for (auto& chain_path : cert_chain_path) {
        auto chain_certificate = security::v3::load_certificate_from_file(chain_path);
        chain.push_back(chain_certificate);
        cert_cache.store(chain_certificate);
    }

    return std::make_unique<security::v3::StaticCertificateProvider>(authorization_ticket, authorization_ticket_key.private_key, chain);
}

std::unique_ptr<security::SecurityEntity>
create_security_entity(const po::variables_map& vm, const Runtime& runtime, PositionProvider& positioning)
{
    std::unique_ptr<security::SecurityEntity> security;
    const std::string name = vm["security"].as<std::string>();

    if (name.empty() || name == "none") {
        // no operation
    } else if (name == "dummy" || name == "dummy-v3") {
        security = create_dummy_v3_security_entity(runtime);
    } else if (name == "dummy-v2") {
        security == create_dummy_v2_security_entity(runtime);
    } else if (name == "certs" || name == "certs-v3" || name == "certs-v2") {
        const unsigned version = name == "certs-v2" ? 2 : 3;

        if (vm.count("certificate") ^ vm.count("certificate-key")) {
            throw std::runtime_error("Either --certificate and --certificate-key must be present or none.");
        }

        if (vm.count("certificate") && vm.count("certificate-key")) {
            const std::string& cert_path = vm["certificate"].as<std::string>();
            const std::string& cert_key_path = vm["certificate-key"].as<std::string>();
            std::vector<std::string> chain_paths;
            if (vm.count("certificate-chain")) {
                chain_paths = vm["certificate-chain"].as<std::vector<std::string>>();
            }

            if (version == 3) {
                auto context = std::make_unique<SecurityContextV3>(runtime, positioning);
                context->cert_provider = load_v3_certificates(cert_path, cert_key_path, chain_paths, context->cert_cache);
                context->build_entity();
                security = std::move(context);
            } else {
                auto context = std::make_unique<SecurityContextV2>(runtime, positioning);
                context->cert_provider = load_v2_certificates(cert_path, cert_key_path, chain_paths, context->cert_cache);
                if (vm.count("trusted-certificate")) {
                    for (auto& cert_path : vm["trusted-certificate"].as<std::vector<std::string> >()) {
                        auto trusted_certificate = security::v2::load_certificate_from_file(cert_path);
                        context->trust_store.insert(trusted_certificate);
                    }
                }
                context->build_entity();
                security = std::move(context);
            }
        } else {
            if (version == 3) {
                auto context = std::make_unique<SecurityContextV3>(runtime, positioning);
                context->cert_provider = std::make_unique<security::v3::NaiveCertificateProvider>(runtime);
                context->build_entity();
                security = std::move(context);
            } else {
                auto context = std::make_unique<SecurityContextV2>(runtime, positioning);
                context->cert_provider = std::make_unique<security::v2::NaiveCertificateProvider>(runtime);
                context->build_entity();
                security = std::move(context);
            }
        }

        if (!security) {
            throw std::runtime_error("internal failure setting up security entity");
        }
    } else {
        throw std::runtime_error("Unknown security entity requested");
    }

    return security;
}

void add_security_options(po::options_description& options)
{
    options.add_options()
        ("security", po::value<std::string>()->default_value("dummy"), "Security entity [none,dummy,certs] (with optional -v2 or -v3 suffix)")
        ("certificate", po::value<std::string>(), "Certificate to use for secured messages.")
        ("certificate-key", po::value<std::string>(), "Certificate key to use for secured messages.")
        ("certificate-chain", po::value<std::vector<std::string> >()->multitoken(), "Certificate chain to use, use as often as needed.")
        ("trusted-certificate", po::value<std::vector<std::string> >()->multitoken(), "Trusted certificate, use as often as needed.")
    ;
}

