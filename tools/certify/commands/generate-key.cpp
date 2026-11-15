#include "generate-key.hpp"
#include "utils.hpp"
#include <boost/program_options.hpp>
#include <vanetza/security/persistence/key_reference.hpp>
#include <iostream>
#include <stdexcept>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;

bool GenerateKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Key reference file.")
        ("security-module", po::value<std::string>(&security_module)->default_value("default"),
            ("Security module creating the key [" + security_module_names() + "].").c_str())
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
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl << std::endl << desc << std::endl;

        return false;
    }

    return true;
}

int GenerateKeyCommand::execute()
{
    std::unique_ptr<SecurityModule> module = create_security_module_or_throw(security_module);

    std::cout << "Generating key... ";
    const expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
    if (!key) {
        throw std::runtime_error("cannot generate key: " + key.error().message());
    }
    std::cout << "OK" << std::endl;

    std::cout << "Writing key reference to '" << output << "'... ";
    const std::error_code error = persistence::save_key_reference(output, *key);
    if (error) {
        // a key without reference is unusable
        module->discard_key(*key);
        throw std::runtime_error("cannot save key reference: " + error.message());
    }
    std::cout << "OK" << std::endl;

    return 0;
}
