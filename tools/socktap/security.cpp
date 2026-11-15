#include "security.hpp"
#include "certificate_validation_v3.hpp"
#include <vanetza/geodesy/country_database.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_credential_provider.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/static_credential_provider.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/naive_credential_provider.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/static_credential_provider.hpp>

#include <chrono>
#include <iostream>
#include <stdexcept>

#ifdef SOCKTAP_WITH_PERSISTENCE
#   include <vanetza/security/persistence/certificate.hpp>
#   include <vanetza/security/persistence/key_reference.hpp>
#endif

using namespace vanetza;
namespace po = boost::program_options;

namespace
{

// setup of socktap reports failures by exceptions
template<typename Certificate>
Certificate load_certificate_file(const std::string& path)
{
#ifdef SOCKTAP_WITH_PERSISTENCE
    expected<Certificate> certificate = security::persistence::load_certificate<Certificate>(path);
    if (!certificate) {
        throw std::runtime_error("cannot load certificate " + path + ": " + certificate.error().message());
    }
    return std::move(*certificate);
#else
    throw std::runtime_error("cannot load certificate " + path + ": socktap is built without persistence feature");
#endif
}

// key reference of a security module's key
security::KeyReference load_key_reference_file(const std::string& path)
{
#ifdef SOCKTAP_WITH_PERSISTENCE
    expected<security::KeyReference> reference = security::persistence::load_key_reference(path);
    if (!reference) {
        throw std::runtime_error("cannot load key reference " + path + ": " + reference.error().message());
    }
    return std::move(*reference);
#else
    throw std::runtime_error("cannot load key reference " + path + ": socktap is built without persistence feature");
#endif
}

std::unique_ptr<security::SecurityModule> create_security_module_or_throw(const std::string& name)
{
    std::unique_ptr<security::SecurityModule> module = security::create_security_module(name);
    if (!module) {
        throw std::runtime_error("security module '" + name + "' is not built in");
    }
    return module;
}

// naive tickets end 22 hours after their issue, renewal leaves a margin of an hour
const std::chrono::hours ticket_renewal_interval { 21 };
const std::chrono::minutes ticket_renewal_retry { 10 };

std::unique_ptr<security::CryptoProvider> create_crypto_provider_or_throw()
{
    std::unique_ptr<security::CryptoProvider> crypto = security::create_crypto_provider();
    if (!crypto) {
        throw std::runtime_error("security requires a crypto provider");
    }
    return crypto;
}

// key reference has to refer to the key of the certificate
void check_certificate_key(security::SecurityModule& module, const security::KeyReference& key,
    const boost::optional<security::PublicKey>& certificate_key, const std::string& key_path,
    const std::string& cert_path)
{
    const expected<security::PublicKey> public_key = module.public_key(key);
    if (!public_key) {
        throw std::runtime_error("cannot use key reference " + key_path + ": " + public_key.error().message());
    } else if (!certificate_key ||
        security::canonical_hexstring(*certificate_key) != security::canonical_hexstring(*public_key)) {
        throw std::runtime_error("key reference " + key_path + " does not belong to certificate " + cert_path);
    }
}

// renews the ticket of a naive credential provider repeatedly, scheduled invocations are assigned to scope
template<typename NaiveCredentialProvider>
void schedule_ticket_renewal(Runtime& runtime, NaiveCredentialProvider& provider, Clock::duration delay,
    const void* scope)
{
    runtime.schedule(delay, [&runtime, &provider, scope](Clock::time_point now) {
        const std::error_code error = provider.issue_certificates(now);
        if (error) {
            std::cerr << "Renewal of naive authorization ticket failed: " << error.message() << std::endl;
            schedule_ticket_renewal(runtime, provider, ticket_renewal_retry, scope);
        } else {
            schedule_ticket_renewal(runtime, provider, ticket_renewal_interval, scope);
        }
    }, scope);
}

// names of built-in security modules including the default
std::string security_module_names()
{
    std::string names = "default";
    for (const std::string& name : security::builtin_security_modules().names()) {
        names += "," + name;
    }
    return names;
}

} // namespace

class SecurityContextV2 : public security::SecurityEntity
{
public:
    SecurityContextV2(Runtime& runtime, PositionProvider& positioning, const std::string& module_name) :
        runtime(runtime), positioning(positioning),
        crypto(create_crypto_provider_or_throw()),
        module(create_security_module_or_throw(module_name)),
        sign_header_policy(runtime, *crypto, positioning),
        trust_store(*crypto),
        cert_cache(runtime, *crypto),
        cert_validator(*crypto, cert_cache, trust_store)
    {
    }

    ~SecurityContextV2()
    {
        // renewals of naive tickets refer to this context
        runtime.cancel(this);
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

    // authorization ticket and chain of certificate files, the ticket's key is referred to by a key reference file
    void use_credential_files(const std::string& cert_path, const std::string& key_path,
        const std::vector<std::string>& chain_paths)
    {
        const auto ticket = load_certificate_file<security::v2::Certificate>(cert_path);
        const security::KeyReference key = load_key_reference_file(key_path);
        check_certificate_key(*module, key, security::v2::get_verification_key(ticket), key_path, cert_path);

        // signer info of type certificate chain includes the AA, see TS 103 097 v1.2.1
        const security::HashedId8* aa_digest = boost::get<security::HashedId8>(&ticket.signer_info);
        boost::optional<security::v2::Certificate> aa_certificate;
        for (auto& chain_path : chain_paths) {
            auto chain_certificate = load_certificate_file<security::v2::Certificate>(chain_path);
            if (aa_digest && security::v2::calculate_hash(*crypto, chain_certificate) == *aa_digest) {
                aa_certificate = chain_certificate;
            }
            cert_cache.insert(chain_certificate);
        }
        if (!aa_certificate) {
            throw std::runtime_error("certificate chain lacks the authorization authority of " + cert_path);
        }
        credentials = std::make_unique<security::v2::StaticCredentialProvider>(ticket, *aa_certificate, key);
    }

    // generated chain whose authorization ticket is renewed before its end of validity
    void use_naive_credentials()
    {
        auto provider = std::make_unique<security::v2::NaiveCredentialProvider>(*module, *crypto);
        const std::error_code error = provider->issue_certificates(runtime.now());
        if (error) {
            throw std::runtime_error("cannot issue naive certificates: " + error.message());
        }
        schedule_ticket_renewal(runtime, *provider, ticket_renewal_interval, this);
        credentials = std::move(provider);
    }

    void build_entity()
    {
        if (!credentials) {
            throw std::runtime_error("credential provider is missing");
        }
        std::unique_ptr<security::SignService> sign_service { new security::v2::SecurityModuleSignService(
            *module, *crypto, *credentials, sign_header_policy) };
        std::unique_ptr<security::CryptoProviderVerifyService> verify_service { new
            security::CryptoProviderVerifyService(runtime, *crypto, positioning) };
        verify_service->use_certificate_cache(&cert_cache);
        verify_service->use_certificate_validator(&cert_validator);
        verify_service->use_sign_header_policy(&sign_header_policy);
        entity.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    }

    Runtime& runtime;
    PositionProvider& positioning;
    std::unique_ptr<security::CryptoProvider> crypto;
    std::unique_ptr<security::SecurityModule> module;
    security::v2::DefaultSignHeaderPolicy sign_header_policy;
    security::v2::TrustStore trust_store;
    security::v2::CertificateCache cert_cache;
    security::v2::DefaultCertificateValidator cert_validator;
    std::unique_ptr<security::v2::CredentialProvider> credentials;
    std::unique_ptr<security::SecurityEntity> entity;
};

class SecurityContextV3 : public security::SecurityEntity
{
public:
    SecurityContextV3(const po::variables_map& options, Runtime& runtime, PositionProvider& positioning,
                      const std::string& module_name, bool permissive_identified_region = false) :
        runtime(runtime), positioning(positioning),
        crypto(create_crypto_provider_or_throw()),
        module(create_security_module_or_throw(module_name)),
        country_database(geodesy::CountryDatabase::embedded()),
        cert_cache(*crypto)
    {
        location_checker.set_permissive_identified_region(permissive_identified_region);
        location_checker.use_country_database(&country_database);
        certificate_validation = create_certificate_validation_v3(
            options, runtime, *crypto, positioning, location_checker);
    }

    ~SecurityContextV3()
    {
        // renewals of naive tickets refer to this context
        runtime.cancel(this);
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

    // authorization ticket and chain of certificate files, the ticket's key is referred to by a key reference file
    void use_credential_files(const std::string& cert_path, const std::string& key_path,
        const std::vector<std::string>& chain_paths)
    {
        const auto ticket = load_certificate_file<security::v3::Certificate>(cert_path);
        const security::KeyReference key = load_key_reference_file(key_path);
        check_certificate_key(*module, key, security::v3::get_public_key(*ticket.content()), key_path, cert_path);

        for (auto& chain_path : chain_paths) {
            auto chain_certificate = load_certificate_file<security::v3::Certificate>(chain_path);
            cert_cache.store(chain_certificate);
            certificate_validation->add_chain_certificate(chain_certificate);
        }
        credentials = std::make_unique<security::v3::StaticCredentialProvider>(ticket, key);
    }

    // generated chain whose authorization ticket is renewed before its end of validity
    void use_naive_credentials()
    {
        auto provider = std::make_unique<security::v3::NaiveCredentialProvider>(*module, *crypto);
        const std::error_code error = provider->issue_certificates(runtime.now());
        if (error) {
            throw std::runtime_error("cannot issue naive certificates: " + error.message());
        }
        certificate_validation->add_chain_certificate(*provider->aa_certificate());
        certificate_validation->add_chain_certificate(*provider->root_certificate());
        schedule_ticket_renewal(runtime, *provider, ticket_renewal_interval, this);
        credentials = std::move(provider);
    }

    void build_entity()
    {
        if (!credentials) {
            throw std::runtime_error("credential provider is missing");
        }
        auto& cert_validator = certificate_validation->validator();
        sign_header_policy.reset(
            new security::v3::DefaultSignHeaderPolicy(runtime, *crypto, positioning, cert_cache));
        std::unique_ptr<security::SignService> sign_service { new security::v3::SecurityModuleSignService(
            *module, *crypto, *credentials, *sign_header_policy, cert_validator) };
        std::unique_ptr<security::CryptoProviderVerifyService> verify_service { new
            security::CryptoProviderVerifyService(runtime, *crypto, positioning) };
        verify_service->use_certificate_cache(&cert_cache);
        verify_service->use_certificate_validator(&cert_validator);
        verify_service->use_sign_header_policy(sign_header_policy.get());
        entity.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    }

    Runtime& runtime;
    PositionProvider& positioning;
    std::unique_ptr<security::CryptoProvider> crypto;
    std::unique_ptr<security::SecurityModule> module;
    geodesy::CountryDatabase country_database;
    security::v3::DefaultLocationChecker location_checker;
    security::v3::CertificateCache cert_cache;
    std::unique_ptr<security::v3::DefaultSignHeaderPolicy> sign_header_policy;
    std::unique_ptr<CertificateValidationV3> certificate_validation;
    std::unique_ptr<security::v3::CredentialProvider> credentials;
    std::unique_ptr<security::SecurityEntity> entity;
};

// dummy security entity owning the crypto provider its verify service identifies certificates with
class DummySecurityContext : public security::SecurityEntity
{
public:
    explicit DummySecurityContext(std::unique_ptr<security::SignService> sign_service) :
        crypto(create_crypto_provider_or_throw())
    {
        std::unique_ptr<security::VerifyService> verify_service { new security::DummyVerifyService {
            *crypto, security::VerificationReport::Success, security::CertificateValidity::valid() } };
        entity.reset(new security::DelegatingSecurityEntity { std::move(sign_service), std::move(verify_service) });
    }

    security::EncapConfirm encapsulate_packet(security::EncapRequest&& request) override
    {
        return entity->encapsulate_packet(std::move(request));
    }

    security::DecapConfirm decapsulate_packet(security::DecapRequest&& request) override
    {
        return entity->decapsulate_packet(std::move(request));
    }

private:
    std::unique_ptr<security::CryptoProvider> crypto;
    std::unique_ptr<security::SecurityEntity> entity;
};

std::unique_ptr<security::SecurityEntity>
create_dummy_v2_security_entity(const Runtime& runtime)
{
    std::unique_ptr<security::SignService> sign_service { new security::v2::DummySignService { runtime, nullptr } };
    return std::make_unique<DummySecurityContext>(std::move(sign_service));
}

std::unique_ptr<security::SecurityEntity>
create_dummy_v3_security_entity(const Runtime& runtime)
{
    std::unique_ptr<security::SignService> sign_service { new security::v3::DummySignService { runtime } };
    return std::make_unique<DummySecurityContext>(std::move(sign_service));
}

std::unique_ptr<security::SecurityEntity>
create_security_entity(const po::variables_map& vm, Runtime& runtime, PositionProvider& positioning)
{
    std::unique_ptr<security::SecurityEntity> security;
    const std::string name = vm["security"].as<std::string>();
    const std::string module_name = vm["security-module"].as<std::string>();

    if (name.empty() || name == "none") {
        // no operation
    } else if (name == "dummy" || name == "dummy-v3") {
        security = create_dummy_v3_security_entity(runtime);
    } else if (name == "dummy-v2") {
        security = create_dummy_v2_security_entity(runtime);
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
                bool permissive_ir = vm.count("security.permissive-identified-region") &&
                                     vm["security.permissive-identified-region"].as<bool>();
                auto context =
                    std::make_unique<SecurityContextV3>(vm, runtime, positioning, module_name, permissive_ir);
                context->use_credential_files(cert_path, cert_key_path, chain_paths);
                context->build_entity();
                security = std::move(context);
            } else {
                auto context = std::make_unique<SecurityContextV2>(runtime, positioning, module_name);
                context->use_credential_files(cert_path, cert_key_path, chain_paths);
                if (vm.count("trusted-certificate")) {
                    for (auto& cert_path : vm["trusted-certificate"].as<std::vector<std::string> >()) {
                        auto trusted_certificate =
                            load_certificate_file<security::v2::Certificate>(cert_path);
                        context->trust_store.insert(trusted_certificate);
                    }
                }
                context->build_entity();
                security = std::move(context);
            }
        } else {
            if (version == 3) {
                bool permissive_ir = vm.count("security.permissive-identified-region") &&
                                     vm["security.permissive-identified-region"].as<bool>();
                auto context =
                    std::make_unique<SecurityContextV3>(vm, runtime, positioning, module_name, permissive_ir);
                context->use_naive_credentials();
                context->build_entity();
                security = std::move(context);
            } else {
                auto context = std::make_unique<SecurityContextV2>(runtime, positioning, module_name);
                context->use_naive_credentials();
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
        ("security-module", po::value<std::string>()->default_value("default"),
         ("Security module holding signing keys [" + security_module_names() + "]").c_str())
        ("certificate", po::value<std::string>(), "Certificate to use for secured messages.")
        ("certificate-key", po::value<std::string>(), "Reference to the certificate's key held by the security module.")
        ("certificate-chain", po::value<std::vector<std::string> >()->multitoken(), "Certificate chain to use, use as often as needed.")
        ("trusted-certificate", po::value<std::vector<std::string> >()->multitoken(), "Trusted certificate, use as often as needed.")
        ("security.permissive-identified-region", po::bool_switch()->default_value(false),
         "Accept IdentifiedRegion certificate constraints without verification (opt-in fallback; see issue #262). Default: reject (OutsideRegion).")
    ;
    add_certificate_validation_v3_options(options);
}
