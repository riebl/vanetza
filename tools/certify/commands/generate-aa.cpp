#include "generate-aa.hpp"
#include <boost/program_options.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <boost/variant/get.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/subject_attribute.hpp>
#include <vanetza/security/subject_info.hpp>

namespace aid = vanetza::aid;
namespace po = boost::program_options;
using namespace vanetza::security;

bool GenerateAaCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
        ("sign-key", po::value<std::string>(&sign_key_path)->required(), "Private key file of the signer.")
        ("sign-cert", po::value<std::string>(&sign_cert_path)->required(), "Private certificate file of the signer.")
        ("subject-key", po::value<std::string>(&subject_key_path)->required(), "Private key file to issue the certificate for.")
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
    BackendCryptoPP crypto_backend;

    std::cout << "Loading keys... ";
    auto sign_key = load_private_key_from_file(sign_key_path);
    ecdsa256::PublicKey subject_key;
    try {
        auto subject_private_key = load_private_key_from_file(subject_key_path);
        subject_key = subject_private_key.public_key;
    } catch (CryptoPP::BERDecodeErr& e) {
        auto subject_key_etsi = load_public_key_from_file(subject_key_path);
        if (get_type(subject_key_etsi) != PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256) {
            std::cerr << "Wrong public key algorithm." << std::endl;
            return 1;
        }

        auto subject_key_etsi_ecdsa = boost::get<ecdsa_nistp256_with_sha256>(subject_key_etsi);
        auto uncompressed_subject_ecc_point = crypto_backend.decompress_point(subject_key_etsi_ecdsa.public_key);
        if (!uncompressed_subject_ecc_point) {
            std::cerr << "Cannot get uncompressed ECC point from public key.";
            return 1;
        } else {
            subject_key = ecdsa256::create_public_key(*uncompressed_subject_ecc_point);
        }
    }
    std::cout << "OK" << std::endl;

    Certificate sign_cert = load_certificate_from_file(sign_cert_path);

    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    Certificate certificate;
    std::list<IntX> certificate_aids;

    if (aids.size()) {
        for (unsigned aid : aids) {
            certificate_aids.push_back(IntX(aid));
        }
    } else {
        certificate_aids.push_back(IntX(aid::CA));
        certificate_aids.push_back(IntX(aid::DEN));
    }
    certificate.subject_attributes.push_back(certificate_aids);

    certificate.signer_info = calculate_hash(sign_cert);

    std::vector<unsigned char> subject(subject_name.begin(), subject_name.end());
    certificate.subject_info.subject_name = subject;
    certificate.subject_info.subject_type = SubjectType::Authorization_Authority;
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    Uncompressed coordinates;
    coordinates.x.assign(subject_key.x.begin(), subject_key.x.end());
    coordinates.y.assign(subject_key.y.begin(), subject_key.y.end());
    EccPoint ecc_point = coordinates;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = ecc_point;
    VerificationKey verification_key;
    verification_key.key = ecdsa;
    certificate.subject_attributes.push_back(verification_key);

    StartAndEndValidity start_and_end;
    start_and_end.start_validity = convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = convert_time32(time_now + std::chrono::hours(24 * validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    std::cout << "Signing certificate... ";

    sort(certificate);
    auto data_buffer = convert_for_signing(certificate);
    certificate.signature = crypto_backend.sign_data(sign_key.private_key, data_buffer);

    std::cout << "OK" << std::endl;

    std::cout << "Writing certificate to '" << output << "'... ";
    save_certificate_to_file(output, certificate);
    std::cout << "OK" << std::endl;

    return 0;
}
