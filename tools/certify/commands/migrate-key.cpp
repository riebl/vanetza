#include "migrate-key.hpp"
#include <boost/program_options.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/persistence/file.hpp>
#include <vanetza/security/persistence/key_reference.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/signing_key_import.hpp>
#include <algorithm>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;

namespace
{

// former versions wrote private keys PEM-encoded or as DER, e.g. PKCS#8 by generate-key
bool is_pem_file(const std::string& path)
{
    static const std::string pem_begin = "-----BEGIN";
    const expected<ByteBuffer> content = persistence::read_file(path);
    if (!content) {
        throw std::runtime_error("cannot read " + path + ": " + content.error().message());
    }
    return content->size() >= pem_begin.size() && std::equal(pem_begin.begin(), pem_begin.end(), content->begin());
}

// names of built-in security modules including the default
std::string security_module_names()
{
    std::string names = "default";
    for (const std::string& name : builtin_security_modules().names()) {
        names += "," + name;
    }
    return names;
}

} // namespace

bool MigrateKeyCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("input", po::value<std::string>(&input)->required(), "Private key file, PEM-encoded or DER.")
        ("output", po::value<std::string>(&output)->required(), "Key reference file.")
        ("security-module", po::value<std::string>(&security_module)->default_value("default"),
            ("Security module importing the key [" + security_module_names() + "].").c_str())
    ;

    po::positional_options_description pos;
    pos.add("input", 1);

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

int MigrateKeyCommand::execute()
{
    std::unique_ptr<SecurityModule> module = create_security_module(security_module);
    if (!module) {
        throw std::runtime_error("security module '" + security_module + "' is not built in");
    }
    SigningKeyImport* key_import = dynamic_cast<SigningKeyImport*>(module.get());
    if (!key_import) {
        throw std::runtime_error("security module '" + security_module + "' cannot import keys");
    }

    std::cout << "Loading private key from '" << input << "'... ";
    const PrivateKey private_key = is_pem_file(input) ?
        load_private_key_from_pem_file(input) : load_private_key_from_der_file(input);
    std::cout << "OK" << std::endl;

    std::cout << "Importing private key into security module... ";
    const expected<KeyReference> reference = key_import->import_signing_key(private_key);
    if (!reference) {
        throw std::runtime_error("cannot import private key: " + reference.error().message());
    }
    std::cout << "OK" << std::endl;

    std::cout << "Writing key reference to '" << output << "'... ";
    const std::error_code error = persistence::save_key_reference(output, *reference);
    if (error) {
        throw std::runtime_error("cannot save key reference: " + error.message());
    }
    std::cout << "OK" << std::endl;

    return 0;
}
