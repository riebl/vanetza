#include "generate-ticket.hpp"
#include "utils.hpp"
#include <boost/program_options.hpp>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <boost/variant/get.hpp>
#include <cryptopp/cryptlib.h>
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

bool GenerateTicketCommand::parse(const std::vector<std::string>& opts)
{
    po::options_description desc("Available options");
    desc.add_options()
        ("help", "Print out available options.")
        ("output", po::value<std::string>(&output)->required(), "Output file.")
        ("sign-key", po::value<std::string>(&sign_key_path)->required(), "Private key file of the signer.")
        ("sign-cert", po::value<std::string>(&sign_cert_path)->required(), "Private certificate file of the signer.")
        ("subject-key", po::value<std::string>(&subject_key_path)->required(), "Private key file to issue the certificate for.")
        ("days", po::value<int>(&validity_days)->default_value(7), "Validity in days.")
        ("cam-permissions", po::value<std::string>(&cam_permissions), "CAM permissions as binary string (e.g. '1111111111111100' to grant all SSPs)")
        ("denm-permissions", po::value<std::string>(&denm_permissions), "DENM permissions as binary string (e.g. '000000000000000000000000' to grant no SSPs)")
        ("permit-gn-mgmt", po::bool_switch(&permit_gn_mgmt), "Generated ticket can be used to sign GN-MGMT messages (e.g. beacons).")
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

int GenerateTicketCommand::execute()
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
        if (get_type(subject_key_etsi_ecdsa.public_key) != EccPointType::Uncompressed) {
            std::cerr << "Unsupported ECC point type, must be uncompressed.";
            return 1;
        }

        subject_key = ecdsa256::create_public_key(boost::get<Uncompressed>(subject_key_etsi_ecdsa.public_key));
    }
    std::cout << "OK" << std::endl;

    auto sign_cert = load_certificate_from_file(sign_cert_path);
    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    auto cam_ssps = vanetza::ByteBuffer({ 1, 0, 0 }); // no special permissions
    auto denm_ssps = vanetza::ByteBuffer({ 1, 0, 0, 0 }); // no special permissions

    if (cam_permissions.size()) {
        permission_string_to_buffer(cam_permissions, cam_ssps);
    }

    if (denm_permissions.size()) {
        permission_string_to_buffer(denm_permissions, denm_ssps);
    }

    Certificate certificate;
    std::list<ItsAidSsp> certificate_ssp;

    // see  ETSI EN 302 637-2 V1.3.1 (2014-09)
    ItsAidSsp certificate_ssp_ca;
    certificate_ssp_ca.its_aid = IntX(aid::CA);
    certificate_ssp_ca.service_specific_permissions = cam_ssps;
    certificate_ssp.push_back(certificate_ssp_ca);

    // see ETSI EN 302 637-3 V1.2.2 (2014-11)
    ItsAidSsp certificate_ssp_den;
    certificate_ssp_den.its_aid = IntX(aid::DEN);
    certificate_ssp_den.service_specific_permissions = denm_ssps;
    certificate_ssp.push_back(certificate_ssp_den);

    if (permit_gn_mgmt) {
        certificate_ssp.push_back({IntX(aid::GN_MGMT), vanetza::ByteBuffer{}});
    }

    certificate.signer_info = calculate_hash(sign_cert);
    certificate.subject_info.subject_type = SubjectType::Authorization_Ticket;
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));
    certificate.subject_attributes.push_back(certificate_ssp);

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
