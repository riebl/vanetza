#include "ethernet_device.hpp"
#include "gps_position_provider.hpp"
#include "bench_in_application.hpp"
#include "cam_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/null_certificate_validator.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/static_certificate_provider.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/trust_store.hpp>

namespace asio = boost::asio;
namespace gn = vanetza::geonet;
namespace po = boost::program_options;
using namespace vanetza;

int main(int argc, const char** argv)
{
    po::options_description options("Allowed options");
    options.add_options()
        ("help", "Print out available options.")
        ("interface,i", po::value<std::string>()->default_value("lo"), "Network interface to use.")
        ("mac-address", po::value<std::string>(), "Override the network interface's MAC address.")
        ("trusted-certificate", po::value<std::vector<std::string> >()->multitoken(), "Trusted certificate for message validation. If no certificates are given, validation will be skipped entirely.")
        ("gpsd-host", po::value<std::string>()->default_value(gpsd::shared_memory), "gpsd's server hostname")
        ("gpsd-port", po::value<std::string>()->default_value(gpsd::default_port), "gpsd's listening port")
        ("require-gnss-fix", "Suppress transmissions while GNSS position fix is missing")
        ("gn-version", po::value<unsigned>()->default_value(1), "GeoNetworking protocol version to use.")
    ;

    po::positional_options_description positional_options;
    positional_options.add("interface", 1);

    po::variables_map vm;

    try {
        po::store(
            po::command_line_parser(argc, argv)
                .options(options)
                .positional(positional_options)
                .run(),
            vm
        );
        po::notify(vm);
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        std::cerr << options << std::endl;
        return 1;
    }

    if (vm.count("help")) {
        std::cout << options << std::endl;
        return 1;
    }

    try {
        asio::io_service io_service;
        TimeTrigger trigger(io_service);

        const char* device_name = vm["interface"].as<std::string>().c_str();
        EthernetDevice device(device_name);
        vanetza::MacAddress mac_address = device.address();

        if (vm.count("mac-address")) {
            std::cout << "Using MAC address: " << vm["mac-address"].as<std::string>() << "." << std::endl;

            if (!parse_mac_address(vm["mac-address"].as<std::string>().c_str(), mac_address)) {
                std::cerr << "The specified MAC address is invalid." << std::endl;
                return 1;
            }
        }

        asio::generic::raw_protocol raw_protocol(AF_PACKET, gn::ether_type.net());
        asio::generic::raw_protocol::socket raw_socket(io_service, raw_protocol);
        raw_socket.bind(device.endpoint(AF_PACKET));

        auto signal_handler = [&io_service](const boost::system::error_code& ec, int signal_number) {
            if (!ec) {
                std::cout << "Termination requested." << std::endl;
                io_service.stop();
            }
        };
        asio::signal_set signals(io_service, SIGINT, SIGTERM);
        signals.async_wait(signal_handler);

        // configure management information base
        gn::MIB mib;
        mib.itsGnLocalGnAddr.mid(mac_address);
        mib.itsGnLocalGnAddr.is_manually_configured(true);
        mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::MANAGED;
        mib.itsGnSecurity = true;
        mib.itsGnProtocolVersion = vm["gn-version"].as<unsigned>();

        if (mib.itsGnProtocolVersion != 0 && mib.itsGnProtocolVersion != 1) {
            throw std::runtime_error("Unsupported GeoNetworking version, only version 0 and 1 are supported.");
        }

        asio::steady_timer gps_timer(io_service);
        GpsPositionProvider positioning(gps_timer, vm["gpsd-host"].as<std::string>(), vm["gpsd-port"].as<std::string>());

        security::TrustStore trust_store;
        security::CertificateCache cert_cache(trigger.runtime());

        auto crypto_backend = security::create_backend("default");
        auto certificate_provider = std::unique_ptr<security::CertificateProvider> {
            new security::NaiveCertificateProvider(trigger.runtime().now()) };
        auto certificate_validator = std::unique_ptr<security::CertificateValidator> {
            new security::DefaultCertificateValidator(*crypto_backend, cert_cache, trust_store) };

        if (vm.count("trusted-certificate")) {
            for (auto& cert_path : vm["trusted-certificate"].as<std::vector<std::string> >()) {
                auto trusted_certificate = security::load_certificate_from_file(cert_path);
                trust_store.insert(trusted_certificate);
            }
        } else {
            mib.itsGnSecurity = false;
        }

        security::DefaultSignHeaderPolicy sign_header_policy(trigger.runtime().now(), positioning);
        security::SignService sign_service = straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy);
        security::VerifyService verify_service = straight_verify_service(trigger.runtime(), *certificate_provider, *certificate_validator, *crypto_backend, cert_cache, sign_header_policy, positioning);
        security::SecurityEntity security_entity(sign_service, verify_service);

        RouterContext context(raw_socket, mib, trigger, positioning, security_entity);
        context.require_position_fix(vm.count("require-gnss-fix") > 0);

        asio::steady_timer bench_timer(io_service);
        BenchInApplication bench_app(trigger.runtime().now(), bench_timer, std::chrono::milliseconds(1000));
        context.enable(&bench_app);

        // We make use of the CAM application here, so certificate requests can be sent out for intermediate certificates
        asio::steady_timer cam_timer(io_service);
        CamApplication cam_app(positioning, trigger.runtime().now(), cam_timer, std::chrono::milliseconds(1000));
        context.enable(&cam_app);

        io_service.run();
    } catch (GpsPositionProvider::gps_error& e) {
        std::cerr << "Exit because of GPS error: " << e.what() << std::endl;
        return 1;
    } catch (std::exception& e) {
        std::cerr << "Exit: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
