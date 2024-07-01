#include "security.hpp"
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/straight_verify_service.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>

#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <vanetza/security/v3/static_certificate_provider.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>

#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <stdexcept>
#include <iostream>

using namespace vanetza;
namespace po = boost::program_options;

class SecurityContext : public security::SecurityEntity
{
public:
    SecurityContext(const Runtime& runtime, PositionProvider& positioning) :
        runtime(runtime), positioning(positioning),
        backend(security::create_backend("default")),
        sign_header_policy(runtime, positioning),
        cert_cache()
        //cert_validator(*backend, cert_cache, trust_store)
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
    security::v2::TrustStore trust_store;
    security::v3::CertificateCache cert_cache;
    //security::v2::DefaultCertificateValidator cert_validator;
};


std::unique_ptr<security::SecurityEntity>
create_security_entity(const po::variables_map& vm, const Runtime& runtime, PositionProvider& positioning)
{
    std::unique_ptr<security::SecurityEntity> security;
    const std::string name = vm["security"].as<std::string>();

    if (name.empty() || name == "none") {
        // no operation
    } else if (name == "dummy") {
        std::unique_ptr<security::SignService> sign_service { new
            vanetza::security::v3::DummySignService { runtime, nullptr } };
        std::unique_ptr<security::VerifyService> verify_service { new
            security::DummyVerifyService {
                security::VerificationReport::Success, security::CertificateValidity::valid() } };
        security.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    } else if (name == "certs") {
        std::unique_ptr<SecurityContext> context { new SecurityContext(runtime, positioning) };

        if (vm.count("certificate") ^ vm.count("certificate-key")) {
            throw std::runtime_error("Either --certificate and --certificate-key must be present or none.");
        }

        if (vm.count("certificate") && vm.count("certificate-key")) {
            const std::string& certificate_path = vm["certificate"].as<std::string>();
            const std::string& certificate_key_path = vm["certificate-key"].as<std::string>();

            auto authorization_ticket = security::v3::load_certificate_from_file(certificate_path);
            auto authorization_ticket_key = security::v3::load_private_key_from_file(certificate_key_path);
            
            std::list<security::v3::Certificate> chain;

            if (vm.count("certificate-chain")) {
                for (auto& chain_path : vm["certificate-chain"].as<std::vector<std::string> >()) {
                    auto chain_certificate = security::v3::load_certificate_from_file(chain_path);
                    chain.push_back(chain_certificate);
                    context->cert_cache.store(chain_certificate);
                }
            }

            context->cert_provider.reset(new security::v3::StaticCertificateProvider(authorization_ticket, authorization_ticket_key.private_key, chain));
        } else {
            context->cert_provider.reset(new security::v3::NaiveCertificateProvider(runtime));
        }

        if (vm.count("trusted-certificate")) {
            for (auto& cert_path : vm["trusted-certificate"].as<std::vector<std::string> >()) {
                auto trusted_certificate = security::v2::load_certificate_from_file(cert_path);
                context->trust_store.insert(trusted_certificate);
            }
        }

        context->build_entity();
        security = std::move(context);
    } else {
        throw std::runtime_error("Unknown security entity requested");
    }

    return security;
}

void add_security_options(po::options_description& options)
{
    options.add_options()
        ("security", po::value<std::string>()->default_value("dummy"), "Security entity [none,dummy,certs]")
        ("certificate", po::value<std::string>(), "Certificate to use for secured messages.")
        ("certificate-key", po::value<std::string>(), "Certificate key to use for secured messages.")
        ("certificate-chain", po::value<std::vector<std::string> >()->multitoken(), "Certificate chain to use, use as often as needed.")
        ("trusted-certificate", po::value<std::vector<std::string> >()->multitoken(), "Trusted certificate, use as often as needed. Root certificates in the chain are automatically trusted.")
    ;
}

