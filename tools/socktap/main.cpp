#include "ethernet_device.hpp"
#include "gps_position_provider.hpp"
#include "hello_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/security_entity.hpp>

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
        ("security", po::value<std::string>()->default_value("off"), "Security profile to use.")
        ("gpsd-host", po::value<std::string>()->default_value(gpsd::shared_memory), "gpsd's server hostname")
        ("gpsd-port", po::value<std::string>()->default_value(gpsd::default_port), "gpsd's listening port")
        ("require-gnss-fix", "suppress transmissions while GNSS position fix is missing")
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
        std::cerr << "ERROR: " << e.what() << "\n\n";
        std::cerr << options << "\n";
        return 1;
    }

    if (vm.count("help")) {
        std::cout << options << "\n";
        return 1;
    }

    try {
        asio::io_service io_service;
        TimeTrigger trigger(io_service);

        const char* device_name = vm["interface"].as<std::string>().c_str();
        EthernetDevice device(device_name);
        vanetza::MacAddress mac_address = device.address();

        if (vm.count("mac-address")) {
            std::cout << "Using MAC address: " << vm["mac-address"].as<std::string>() << ".\n";

            if (!parse_mac_address(vm["mac-address"].as<std::string>().c_str(), mac_address)) {
                std::cerr << "The specified MAC address is invalid." << "\n";
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
        // TODO: make more MIB options configurable by command line flags
        gn::MIB mib;
        mib.itsGnLocalGnAddr.mid(mac_address);
        mib.itsGnLocalGnAddr.is_manually_configured(true);
        mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::MANAGED;

        // We always use the same ceritificate manager and crypto services for now.
        // If itsGnSecurity is false, no signing will be performed, but receiving of signed messages works as expected.
        security::NaiveCertificateProvider naive_cert_provider(trigger.runtime().now());
        auto crypto_backend = security::create_backend("default");
        security::SignService sign_service = straight_sign_service(trigger.runtime(), naive_cert_provider, *crypto_backend);
        security::VerifyService verify_service = dummy_verify_service(security::VerificationReport::Success, security::CertificateValidity::valid());

        const std::string& security_option = vm["security"].as<std::string>();
        if (security_option == "off") {
            mib.itsGnSecurity = false;
        } else if (security_option == "naive") {
            mib.itsGnSecurity = true;
        } else {
            std::cerr << "Invalid security option '" << security_option << "', falling back to 'off'." << "\n";
            mib.itsGnSecurity = false;
        }

        GpsPositionProvider positioning(vm["gpsd-host"].as<std::string>(), vm["gpsd-port"].as<std::string>());
        security::SecurityEntity security_entity(sign_service, verify_service);
        RouterContext context(raw_socket, mib, trigger, positioning, security_entity);
        context.require_position_fix(vm.count("require-gnss-fix") > 0);

        asio::steady_timer hello_timer(io_service);
        HelloApplication hello_app(hello_timer);
        context.enable(&hello_app);

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
