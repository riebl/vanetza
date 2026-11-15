#include "generate-aa.hpp"
#include "utils.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/subject_attribute.hpp>
#include <vanetza/security/v2/subject_info.hpp>

namespace po = boost::program_options;
using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v2;

bool GenerateAaCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
        ("sign-key", po::value<std::string>(&sign_key_path)->required(), "Key reference file of the signer.")
        ("sign-cert", po::value<std::string>(&sign_cert_path)->required(), "Certificate file of the signer.")
        ("subject-key", po::value<std::string>(&subject_key_path)->required(),
            "Key reference or PEM SubjectPublicKeyInfo file of the subject.")
        ("security-module", po::value<std::string>(&security_module)->default_value("default"),
            ("Security module holding the referenced keys [" + security_module_names() + "].").c_str())
        ("subject-name", po::value<std::string>(&subject_name)->default_value("Hello World Auth-CA"), "Subject name.")
        ("days", po::value<int>(&validity_days)->default_value(180), "Validity in days.")
        ("aid", po::value<std::vector<unsigned> >(&aids)->multitoken(), "Allowed ITS-AIDs to restrict permissions, defaults to 36 (CA) and 37 (DEN) if empty.")
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

int GenerateAaCommand::execute()
{
    std::unique_ptr<SecurityModule> module = create_security_module_or_throw(security_module);
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider_or_throw();

    std::cout << "Loading keys... ";
    const KeyReference sign_key = load_key_reference_or_throw(sign_key_path);
    const security::PublicKey subject_key = load_subject_key_or_throw(subject_key_path, *module);
    std::cout << "OK" << std::endl;

    const Certificate sign_cert = load_v2_certificate_or_throw(sign_cert_path);

    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    Certificate certificate;
    std::list<v2::IntX> certificate_aids;

    if (aids.size()) {
        for (unsigned aid : aids) {
            certificate_aids.push_back(v2::IntX(aid));
        }
    } else {
        certificate_aids.push_back(v2::IntX(aid::CA));
        certificate_aids.push_back(v2::IntX(aid::DEN));
    }
    certificate.subject_attributes.push_back(certificate_aids);

    certificate.signer_info = calculate_hash(*crypto, sign_cert);

    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;
    certificate.subject_info.subject_type = SubjectType::Authorization_Authority;
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    certificate.subject_attributes.push_back(make_v2_verification_key(subject_key));

    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(time_now + std::chrono::hours(24 * validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    std::cout << "Signing certificate... ";

    sign_v2_certificate_or_throw(certificate, *module, *crypto, sign_key);

    std::cout << "OK" << std::endl;

    std::cout << "Writing certificate to '" << output << "'... ";
    save_v2_certificate_or_throw(output, certificate);
    std::cout << "OK" << std::endl;

    return 0;
}
