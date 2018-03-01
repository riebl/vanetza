#include "cases/security/signing.hpp"
#include "cases/security/validation.hpp"
#include "options.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <memory>

namespace po = boost::program_options;

std::unique_ptr<Case> parse_options(int argc, const char *argv[])
{
    po::options_description global("Global options");
    global.add_options()
        ("case", po::value<std::string>(), "Case to execute.")
        ("subargs", po::value<std::vector<std::string>>(), "Arguments for case.");

    po::positional_options_description pos;
    pos.add("case", 1);
    pos.add("subargs", -1);

    po::variables_map vm;

    po::parsed_options parsed = po::command_line_parser(argc, argv)
        .options(global)
        .positional(pos)
        .allow_unregistered()
        .run();

    po::store(parsed, vm);
    po::notify(vm);

    std::string available_commands = "Available cases: security-validation, security-signing";

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
    } else if (name == "security-signing") {
        instance.reset(new SecuritySigningCase());
    } else if (name == "security-validation") {
        instance.reset(new SecurityValidationCase());
    } else {
        throw std::runtime_error("Unknown benchmark case.");
    }

    std::vector<std::string> opts = po::collect_unrecognized(parsed.options, po::include_positional);
    opts.erase(opts.begin());

    if (!instance->parse(opts)) {
        return nullptr;
    }

    return instance;
}
