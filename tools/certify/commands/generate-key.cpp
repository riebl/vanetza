#include "generate-key.hpp"
#include <boost/program_options.hpp>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/persistence.hpp>

namespace po = boost::program_options;
using namespace vanetza::security;

bool GenerateKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
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
    auto backend = create_backend_or_throw("default");

    std::cout << "Generating key... ";
    auto key_pair = backend->generate_key_pair();
    std::cout << "OK" << std::endl;

    std::cout << "Writing key to '" << output << "'... ";
    std::ofstream ofs(output, std::ios::binary);
    save_private_key_pkcs8_der(ofs, key_pair);
    std::cout << "OK" << std::endl;

    return 0;
}
