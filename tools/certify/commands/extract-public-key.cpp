#include "extract-public-key.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <stdexcept>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/persistence.hpp>

namespace po = boost::program_options;
using namespace vanetza::security;

bool ExtractPublicKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
        ("certificate", po::value<std::string>(&certificate_path), "Certificate file to extract public key from.")
        ("private-key", po::value<std::string>(&private_key_path), "Private key file to extract public key from.")
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

        if (!(vm.count("certificate") ^ vm.count("private-key"))) {
            std::cerr << "Error: One of certificate / private-key parameters must be present." << std::endl;

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

    std::unique_ptr<Backend> backend = create_backend("default");
    ecdsa256::PublicKey public_key;
    if (certificate_path.length() > 0) {
        auto certificate = load_certificate_from_file(certificate_path);
        auto certificate_key = get_public_key(certificate, *backend);

        if (!certificate_key) {
            std::cerr << "Reading public key from certificate failed." << std::endl;
        }

        public_key = *certificate_key;
    } else {
        auto private_key = load_private_key_from_file(private_key_path);
        public_key = private_key.public_key;
    }

    std::cout << "OK" << std::endl;

    Uncompressed coordinates;
    coordinates.x.assign(public_key.x.begin(), public_key.x.end());
    coordinates.y.assign(public_key.y.begin(), public_key.y.end());

    ecdsa_nistp256_with_sha256 public_key_etsi;
    public_key_etsi.public_key = coordinates;

    std::cout << "Writing public key to '" << output << "'... ";
    save_public_key_to_file(output, public_key_etsi);
    std::cout << "OK" << std::endl;

    return 0;
}
