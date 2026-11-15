#include "extract-public-key.hpp"
#include "utils.hpp"
#include <boost/program_options.hpp>
#include <vanetza/security/persistence/public_key.hpp>
#include <iostream>
#include <stdexcept>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;

bool ExtractPublicKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Public key file (PEM SubjectPublicKeyInfo).")
        ("certificate", po::value<std::string>(&certificate_path), "Certificate file to extract public key from.")
        ("key", po::value<std::string>(&key_path), "Key reference file to extract public key from.")
        ("security-module", po::value<std::string>(&security_module)->default_value("default"),
            ("Security module holding the referenced key [" + security_module_names() + "].").c_str())
    ;

    po::positional_options_description pos;
    pos.add("output", 1);

    po::variables_map vm;
    po::store(po::command_line_parser(opts).options(desc).positional(pos).run(), vm);

    if (vm.count("help")) {
        std::cerr << desc << std::endl;

        return false;
    }

    try {
        po::notify(vm);

        if (!(vm.count("certificate") ^ vm.count("key"))) {
            std::cerr << "Error: One of certificate / key parameters must be present." << std::endl;

            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl << desc << std::endl;

        return false;
    }

    return true;
}

int ExtractPublicKeyCommand::execute()
{
    std::cout << "Loading key... ";
    PublicKey public_key;
    if (!certificate_path.empty()) {
        const v2::Certificate certificate = load_v2_certificate_or_throw(certificate_path);
        const boost::optional<PublicKey> certificate_key = v2::get_verification_key(certificate);
        if (!certificate_key) {
            throw std::runtime_error("certificate " + certificate_path + " lacks a verification key");
        }
        public_key = *certificate_key;
    } else {
        std::unique_ptr<SecurityModule> module = create_security_module_or_throw(security_module);
        const expected<PublicKey> referenced_key = module->public_key(load_key_reference_or_throw(key_path));
        if (!referenced_key) {
            throw std::runtime_error("cannot use key reference " + key_path + ": " + referenced_key.error().message());
        }
        public_key = *referenced_key;
    }
    std::cout << "OK" << std::endl;

    std::cout << "Writing public key to '" << output << "'... ";
    const std::error_code error = persistence::save_public_key_pem(output, public_key);
    if (error) {
        throw std::runtime_error("cannot save public key: " + error.message());
    }
    std::cout << "OK" << std::endl;

    return 0;
}
