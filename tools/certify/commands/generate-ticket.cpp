#include "generate-ticket.hpp"
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

bool GenerateTicketCommand::parse(const std::vector<std::string>& opts)
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
    std::unique_ptr<SecurityModule> module = create_security_module_or_throw(security_module);
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider_or_throw();

    std::cout << "Loading keys... ";
    const KeyReference sign_key = load_key_reference_or_throw(sign_key_path);
    const PublicKey subject_key = load_subject_key_or_throw(subject_key_path, *module);
    std::cout << "OK" << std::endl;

    const v2::Certificate sign_cert = load_v2_certificate_or_throw(sign_cert_path);
    auto time_now = vanetza::Clock::at(boost::posix_time::microsec_clock::universal_time());

    auto cam_ssps = vanetza::ByteBuffer({ 1, 0, 0 }); // no special permissions
    auto denm_ssps = vanetza::ByteBuffer({ 1, 0, 0, 0 }); // no special permissions

    if (cam_permissions.size()) {
        permission_string_to_buffer(cam_permissions, cam_ssps);
    }

    if (denm_permissions.size()) {
        permission_string_to_buffer(denm_permissions, denm_ssps);
    }

    v2::Certificate certificate;
    std::list<v2::ItsAidSsp> certificate_ssp;

    // see  ETSI EN 302 637-2 V1.3.1 (2014-09)
    v2::ItsAidSsp certificate_ssp_ca;
    certificate_ssp_ca.its_aid = v2::IntX(aid::CA);
    certificate_ssp_ca.service_specific_permissions = cam_ssps;
    certificate_ssp.push_back(certificate_ssp_ca);

    // see ETSI EN 302 637-3 V1.2.2 (2014-11)
    v2::ItsAidSsp certificate_ssp_den;
    certificate_ssp_den.its_aid = v2::IntX(aid::DEN);
    certificate_ssp_den.service_specific_permissions = denm_ssps;
    certificate_ssp.push_back(certificate_ssp_den);

    if (permit_gn_mgmt) {
        certificate_ssp.push_back({v2::IntX(aid::GN_MGMT), vanetza::ByteBuffer{}});
    }

    certificate.signer_info = calculate_hash(*crypto, sign_cert);
    certificate.subject_info.subject_type = v2::SubjectType::Authorization_Ticket;
    certificate.subject_attributes.push_back(v2::SubjectAssurance(0x00));
    certificate.subject_attributes.push_back(certificate_ssp);

    certificate.subject_attributes.push_back(make_v2_verification_key(subject_key));

    v2::StartAndEndValidity start_and_end;
    start_and_end.start_validity = v2::convert_time32(time_now - std::chrono::hours(1));
    start_and_end.end_validity = v2::convert_time32(time_now + std::chrono::hours(24 * validity_days));
    certificate.validity_restriction.push_back(start_and_end);

    std::cout << "Signing certificate... ";

    sign_v2_certificate_or_throw(certificate, *module, *crypto, sign_key);

    std::cout << "OK" << std::endl;

    std::cout << "Writing certificate to '" << output << "'... ";
    save_v2_certificate_or_throw(output, certificate);
    std::cout << "OK" << std::endl;

    return 0;
}
