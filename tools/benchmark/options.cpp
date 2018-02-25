#include "cases/security/validate_certificate.hpp"
#include "cases/security/validate_certificate_hash.hpp"
#include "options.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

std::unique_ptr<Case> parse_options(int argc, const char *argv[])
{
    po::options_description global("Global options");
    global.add_options()("case", po::value<std::string>(), "Case to execute.");

    po::positional_options_description pos;
    pos.add("case", 1);

    po::variables_map vm;

    po::parsed_options parsed = po::command_line_parser(argc, argv)
        .options(global)
        .positional(pos)
        .allow_unregistered()
        .run();

    po::store(parsed, vm);
    po::notify(vm);

    std::string available_commands = "Available cases: security-validate-certificate, security-validate-certificate-hash";

    if (!vm.count("case")) {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;

        return nullptr;
    }

    std::string name = vm["case"].as<std::string>();
    std::unique_ptr<Case> instance;

    if (name == "--help") {
        std::cerr << global << std::endl;
        std::cerr << available_commands << std::endl;
    } else if (name == "security-validate-certificate") {
        instance.reset(new SecurityValidateCertificateCase());
    } else if (name == "security-validate-certificate-hash") {
        instance.reset(new SecurityValidateCertificateHashCase());
    } else {
        // unrecognized command
        throw po::invalid_option_value(name);
    }

    return instance;
}
