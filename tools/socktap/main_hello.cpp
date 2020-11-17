#include "ethernet_device.hpp"
#include "positioning.hpp"
#include "hello_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <vanetza/security/delegating_security_entity.hpp>

namespace asio = boost::asio;
namespace gn = vanetza::geonet;
namespace po = boost::program_options;
using namespace vanetza;

int main(int argc, const char** argv)
{
    po::options_description options("Allowed options");
    options.add_options()
        ("help", "Print out available options.")
        ("link-layer,l", po::value<std::string>()->default_value("ethernet"), "Link layer type")
        ("interface,i", po::value<std::string>()->default_value("lo"), "Network interface to use.")
        ("mac-address", po::value<std::string>(), "Override the network interface's MAC address.")
        ("require-gnss-fix", "Suppress transmissions while GNSS position fix is missing")
    ;
    add_positioning_options(options);

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
            std::cout << "Using custom MAC address: " << vm["mac-address"].as<std::string>() << "." << std::endl;

            if (!parse_mac_address(vm["mac-address"].as<std::string>().c_str(), mac_address)) {
                std::cerr << "The specified MAC address is invalid." << std::endl;
                return 1;
            }
        }

        const std::string link_layer_name = vm["link-layer"].as<std::string>();
        auto link_layer =  create_link_layer(io_service, device, link_layer_name);
        if (!link_layer) {
            std::cerr << "No link layer '" << link_layer_name << "' found." << std::endl;
            return 1;
        }

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
        mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::Managed;
        mib.itsGnSecurity = false;

        auto positioning = create_position_provider(io_service, vm, trigger.runtime());
        if (!positioning) {
            std::cerr << "Requested positioning method is not available." << std::endl;
            return 1;
        }

        security::SignService sign_service = security::dummy_sign_service(trigger.runtime(), nullptr);
        security::VerifyService verify_service =
            security::dummy_verify_service(security::VerificationReport::Success, security::CertificateValidity::valid());
        security::DelegatingSecurityEntity security_entity(sign_service, verify_service);

        RouterContext context(mib, trigger, *positioning, &security_entity);
        context.require_position_fix(vm.count("require-gnss-fix") > 0);
        context.set_link_layer(link_layer.get());

        HelloApplication hello_app(io_service, std::chrono::milliseconds(800));
        context.enable(&hello_app);

        io_service.run();
    } catch (PositioningException& e) {
        std::cerr << "Exit because of positioning error: " << e.what() << std::endl;
        return 1;
    } catch (std::exception& e) {
        std::cerr << "Exit: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
