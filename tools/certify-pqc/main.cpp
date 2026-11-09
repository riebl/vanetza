#include "certificate_builder.hpp"
#include "files.hpp"
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_crypto_provider.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/pqc/hybrid_certificate.hpp>
#include <vanetza/security/pqc/hybrid_certificate_validator.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v3;
namespace builder = vanetza::security::pqc::certificate_builder;

namespace
{

enum class CertificateProfile
{
    Ecc,
    Hybrid
};

CertificateProfile parse_profile(const std::string& profile)
{
    if (profile == "ecc") {
        return CertificateProfile::Ecc;
    }
    if (profile == "hybrid") {
        return CertificateProfile::Hybrid;
    }
    throw std::invalid_argument("unknown certificate profile: " + profile);
}

void validate_pqc_argument(
    CertificateProfile profile, const std::string& value, const char* option)
{
    if (profile == CertificateProfile::Hybrid && value.empty()) {
        throw std::invalid_argument(std::string(option) + " is required for the hybrid profile");
    }
    if (profile == CertificateProfile::Ecc && !value.empty()) {
        throw std::invalid_argument(std::string(option) + " is not valid for the ECC profile");
    }
}

Clock::time_point now()
{
    return Clock::at(boost::posix_time::microsec_clock::universal_time());
}

std::vector<ItsAid> convert_aids(const std::vector<unsigned>& input)
{
    return std::vector<ItsAid>(input.begin(), input.end());
}

std::vector<std::string> command_arguments(int argc, const char* argv[])
{
    return std::vector<std::string>(argv + 2, argv + argc);
}

po::variables_map parse(
    const std::vector<std::string>& arguments, const po::options_description& options,
    const po::positional_options_description& positional = {})
{
    po::variables_map variables;
    po::store(po::command_line_parser(arguments)
        .options(options).positional(positional).run(), variables);
    if (!variables.count("help")) {
        po::notify(variables);
    }
    return variables;
}

int generate_key(const std::vector<std::string>& arguments)
{
    std::string output;
    po::options_description options("Generate an FN-DSA-512 key pair");
    options.add_options()
        ("help,h", "Show this help")
        ("output", po::value<std::string>(&output)->required(),
            "Output base path; .pqc.key and .pqc.pub are appended");
    po::positional_options_description positional;
    positional.add("output", 1);
    const auto variables = parse(arguments, options, positional);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    auto backend = pqc::create_fndsa512_backend();
    save_pqc_key_pair(output, backend->generate_key_pair());
    std::cout << "Wrote " << output << ".pqc.key and " << output << ".pqc.pub\n";
    return 0;
}

builder::CertificateParameters certificate_parameters(
    const std::string& name, int days, const std::vector<unsigned>& aids)
{
    builder::CertificateParameters parameters;
    parameters.subject_name = name;
    parameters.validity_days = days;
    parameters.application_ids = convert_aids(aids);
    return parameters;
}

int generate_root(const std::vector<std::string>& arguments)
{
    std::string output;
    std::string subject_key;
    std::string subject_pqc_key;
    std::string profile_name = "hybrid";
    std::string subject_name = "Hello World Root-CA";
    int days = 365;
    std::vector<unsigned> aids;
    po::options_description options("Generate a V3 Root CA certificate");
    options.add_options()
        ("help,h", "Show this help")
        ("output,o", po::value<std::string>(&output)->required(), "Output certificate")
        ("subject-key", po::value<std::string>(&subject_key)->required(), "ECC private key")
        ("profile", po::value<std::string>(&profile_name)->default_value("hybrid"),
            "Certificate profile: ecc or hybrid")
        ("subject-pqc-key", po::value<std::string>(&subject_pqc_key),
            "FN-DSA key base path")
        ("subject-name", po::value<std::string>(&subject_name), "Certificate subject name")
        ("days", po::value<int>(&days), "Validity in days")
        ("aid", po::value<std::vector<unsigned>>(&aids)->multitoken(), "Permitted ITS-AIDs");
    const auto variables = parse(arguments, options);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    const auto profile = parse_profile(profile_name);
    validate_pqc_argument(profile, subject_pqc_key, "--subject-pqc-key");
    auto ecc_backend = create_backend_or_throw("default");
    const auto subject_ecc = load_ecc_key_pair(subject_key);
    Certificate certificate;
    if (profile == CertificateProfile::Hybrid) {
        auto pqc_backend = pqc::create_fndsa512_backend();
        certificate = builder::build_hybrid_root_certificate(
            *ecc_backend, *pqc_backend, subject_ecc, load_pqc_key_pair(subject_pqc_key),
            certificate_parameters(subject_name, days, aids), now());
    } else {
        certificate = builder::build_ecc_root_certificate(
            *ecc_backend, subject_ecc,
            certificate_parameters(subject_name, days, aids), now());
    }
    save_v3_certificate(output, certificate);
    std::cout << "Wrote " << profile_name << " V3 Root CA certificate " << output << '\n';
    return 0;
}

int generate_aa(const std::vector<std::string>& arguments)
{
    std::string output;
    std::string sign_key;
    std::string sign_cert;
    std::string sign_pqc_key;
    std::string subject_key;
    std::string subject_pqc_key;
    std::string profile_name = "hybrid";
    std::string subject_name = "Hello World Auth-CA";
    int days = 180;
    std::vector<unsigned> aids;
    po::options_description options("Generate a V3 Authorization Authority certificate");
    options.add_options()
        ("help,h", "Show this help")
        ("output,o", po::value<std::string>(&output)->required(), "Output certificate")
        ("sign-key", po::value<std::string>(&sign_key)->required(), "Issuer ECC private key")
        ("sign-cert", po::value<std::string>(&sign_cert)->required(), "Issuer certificate")
        ("profile", po::value<std::string>(&profile_name)->default_value("hybrid"),
            "Certificate profile: ecc or hybrid")
        ("sign-pqc-key", po::value<std::string>(&sign_pqc_key),
            "Issuer FN-DSA key base path")
        ("subject-key", po::value<std::string>(&subject_key)->required(), "Subject ECC private key")
        ("subject-pqc-key", po::value<std::string>(&subject_pqc_key),
            "Subject FN-DSA key base path")
        ("subject-name", po::value<std::string>(&subject_name), "Certificate subject name")
        ("days", po::value<int>(&days), "Validity in days")
        ("aid", po::value<std::vector<unsigned>>(&aids)->multitoken(), "Permitted ITS-AIDs");
    const auto variables = parse(arguments, options);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    const auto profile = parse_profile(profile_name);
    validate_pqc_argument(profile, sign_pqc_key, "--sign-pqc-key");
    validate_pqc_argument(profile, subject_pqc_key, "--subject-pqc-key");
    auto ecc_backend = create_backend_or_throw("default");
    const auto subject_ecc = load_ecc_key_pair(subject_key);
    const auto issuer_ecc = load_ecc_key_pair(sign_key);
    const auto issuer_certificate = load_v3_certificate(sign_cert);
    Certificate certificate;
    if (profile == CertificateProfile::Hybrid) {
        auto pqc_backend = pqc::create_fndsa512_backend();
        const auto subject_pqc = load_pqc_key_pair(subject_pqc_key);
        certificate = builder::build_hybrid_authorization_authority_certificate(
            *ecc_backend, *pqc_backend, issuer_ecc,
            load_pqc_private_key(sign_pqc_key), issuer_certificate,
            subject_ecc.public_key, subject_pqc.public_key,
            certificate_parameters(subject_name, days, aids), now());
    } else {
        certificate = builder::build_ecc_authorization_authority_certificate(
            *ecc_backend, issuer_ecc, issuer_certificate, subject_ecc.public_key,
            certificate_parameters(subject_name, days, aids), now());
    }
    save_v3_certificate(output, certificate);
    std::cout << "Wrote " << profile_name
              << " V3 Authorization Authority certificate " << output << '\n';
    return 0;
}

int generate_ticket(const std::vector<std::string>& arguments)
{
    std::string output;
    std::string sign_key;
    std::string sign_cert;
    std::string sign_pqc_key;
    std::string subject_key;
    std::string profile_name = "hybrid";
    int days = 7;
    std::vector<unsigned> aids;
    po::options_description options("Generate a V3 Authorization Ticket");
    options.add_options()
        ("help,h", "Show this help")
        ("output,o", po::value<std::string>(&output)->required(), "Output certificate")
        ("sign-key", po::value<std::string>(&sign_key)->required(), "Issuer ECC private key")
        ("sign-cert", po::value<std::string>(&sign_cert)->required(), "Issuer certificate")
        ("profile", po::value<std::string>(&profile_name)->default_value("hybrid"),
            "Certificate profile: ecc or hybrid")
        ("sign-pqc-key", po::value<std::string>(&sign_pqc_key),
            "Issuer FN-DSA key base path")
        ("subject-key", po::value<std::string>(&subject_key)->required(), "Subject ECC private key")
        ("days", po::value<int>(&days), "Validity in days")
        ("aid", po::value<std::vector<unsigned>>(&aids)->multitoken(), "Permitted ITS-AIDs");
    const auto variables = parse(arguments, options);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    const auto profile = parse_profile(profile_name);
    validate_pqc_argument(profile, sign_pqc_key, "--sign-pqc-key");
    auto ecc_backend = create_backend_or_throw("default");
    const auto issuer_ecc = load_ecc_key_pair(sign_key);
    const auto issuer_certificate = load_v3_certificate(sign_cert);
    const auto subject_ecc = load_ecc_key_pair(subject_key);
    Certificate certificate;
    if (profile == CertificateProfile::Hybrid) {
        auto pqc_backend = pqc::create_fndsa512_backend();
        certificate = builder::build_hybrid_authorization_ticket(
            *ecc_backend, *pqc_backend, issuer_ecc,
            load_pqc_private_key(sign_pqc_key), issuer_certificate,
            subject_ecc.public_key, certificate_parameters({}, days, aids), now());
    } else {
        certificate = builder::build_ecc_authorization_ticket(
            *ecc_backend, issuer_ecc, issuer_certificate, subject_ecc.public_key,
            certificate_parameters({}, days, aids), now());
    }
    save_v3_certificate(output, certificate);
    std::cout << "Wrote " << profile_name << " V3 Authorization Ticket " << output << '\n';
    return 0;
}

const char* material_state(pqc::MaterialState state)
{
    switch (state) {
        case pqc::MaterialState::None: return "none";
        case pqc::MaterialState::Authority: return "authority (key + signature)";
        case pqc::MaterialState::EndEntity: return "end entity (signature only)";
        case pqc::MaterialState::Inconsistent: return "inconsistent";
    }
    return "unknown";
}

int show_certificate(const std::vector<std::string>& arguments)
{
    std::string input;
    po::options_description options("Show V3 certificate information");
    options.add_options()
        ("help,h", "Show this help")
        ("certificate", po::value<std::string>(&input)->required(), "Certificate file");
    po::positional_options_description positional;
    positional.add("certificate", 1);
    const auto variables = parse(arguments, options, positional);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    const auto certificate = load_v3_certificate(input);
    const auto key = pqc::get_alternative_public_key(certificate);
    const auto signature = pqc::get_alternative_signature(certificate);
    std::cout << "Encoded size: " << certificate.encode().size() << " bytes\n"
              << "Alternative material: "
              << material_state(pqc::alternative_material_state(certificate)) << "\n"
              << "FN-DSA-512 public key: " << (key ? key->bytes.size() : 0) << " bytes\n"
              << "FN-DSA-512 signature: " << (signature ? signature->bytes.size() : 0)
              << " bytes\n";
    return 0;
}

int verify_chain(const std::vector<std::string>& arguments)
{
    std::string root_path;
    std::string aa_path;
    std::string ticket_path;
    std::string profile_name = "hybrid";
    unsigned application_id = aid::CA;
    po::options_description options("Verify a V3 Root -> AA -> AT chain");
    options.add_options()
        ("help,h", "Show this help")
        ("root", po::value<std::string>(&root_path)->required(), "Trusted Root certificate")
        ("aa", po::value<std::string>(&aa_path)->required(), "Authorization Authority certificate")
        ("ticket", po::value<std::string>(&ticket_path)->required(), "Authorization Ticket certificate")
        ("profile", po::value<std::string>(&profile_name)->default_value("hybrid"),
            "Expected profile: ecc or hybrid")
        ("aid", po::value<unsigned>(&application_id), "ITS-AID to validate (default: 36)");
    const auto variables = parse(arguments, options);
    if (variables.count("help")) {
        std::cout << options << '\n';
        return 0;
    }

    const auto root = load_v3_certificate(root_path);
    const auto aa = load_v3_certificate(aa_path);
    const auto ticket = load_v3_certificate(ticket_path);
    const auto profile = parse_profile(profile_name);
    if (profile == CertificateProfile::Ecc &&
        (pqc::alternative_material_state(root) != pqc::MaterialState::None ||
         pqc::alternative_material_state(aa) != pqc::MaterialState::None ||
         pqc::alternative_material_state(ticket) != pqc::MaterialState::None)) {
        throw std::invalid_argument("ECC profile chain contains alternative PQC material");
    }
    auto ecc_backend = create_backend_or_throw("default");
    auto pqc_backend = pqc::create_fndsa512_backend();

    BackendCryptoProvider ecc_crypto { *ecc_backend };
    TrustStore trust_store { ecc_crypto };
    trust_store.insert(root);
    IssuerMemoryLookup issuer_lookup { ecc_crypto };
    if (!issuer_lookup.insert(root) || !issuer_lookup.insert(aa)) {
        throw std::runtime_error("Root or AA cannot be used as an issuer certificate");
    }

    ManualRuntime runtime(now());
    pqc::HybridCertificateValidator validator;
    validator.use_runtime(&runtime);
    validator.disable_location_checks(true);
    validator.use_issuer_lookup(&issuer_lookup);
    validator.use_trust_store(&trust_store);
    validator.use_backends(ecc_backend.get(), pqc_backend.get());
    validator.use_verification_policy(profile == CertificateProfile::Hybrid ?
        pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired :
        pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent);

    const auto verdict = validator.valid_for_signing(ticket, application_id);
    if (verdict != CertificateValidator::Verdict::Valid) {
        std::cerr << profile_name << " chain verification failed (verdict "
                  << static_cast<int>(verdict) << ")\n";
        return 1;
    }
    std::cout << profile_name << " V3 Root -> AA -> AT chain is valid\n";
    return 0;
}

void print_usage(const char* executable)
{
    std::cout << "Usage: " << executable << " COMMAND [OPTIONS]\n\n"
              << "Commands:\n"
              << "  generate-key       Generate an FN-DSA-512 key pair\n"
              << "  generate-root      Generate a V3 Root CA\n"
              << "  generate-aa        Generate a V3 Authorization Authority\n"
              << "  generate-ticket    Generate a V3 Authorization Ticket\n"
              << "  show               Show V3 certificate material\n"
              << "  verify-chain       Verify a Root -> AA -> AT chain\n";
}

} // namespace

int main(int argc, const char* argv[])
{
    try {
        if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
            print_usage(argv[0]);
            return argc < 2 ? 1 : 0;
        }

        const std::string command = argv[1];
        const auto arguments = command_arguments(argc, argv);
        if (command == "generate-key") {
            return generate_key(arguments);
        }
        if (command == "generate-root") {
            return generate_root(arguments);
        }
        if (command == "generate-aa") {
            return generate_aa(arguments);
        }
        if (command == "generate-ticket") {
            return generate_ticket(arguments);
        }
        if (command == "show") {
            return show_certificate(arguments);
        }
        if (command == "verify-chain") {
            return verify_chain(arguments);
        }
        throw std::invalid_argument("unknown command: " + command);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
