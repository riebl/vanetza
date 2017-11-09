#include "ethernet_device.hpp"
#include "fake_network_device.hpp"
#include "gps_position_provider.hpp"
#include "hello_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/program_options.hpp>
#include <iostream>

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
        ("mac-address", po::value<std::string>(), "Fake the sender MAC address.")
    ;

    po::positional_options_description positional_options;
    positional_options.add("interface", -1);

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
        vanetza::MacAddress address;
        NetworkDevice *device = new EthernetDevice(vm["interface"].as<std::string>().c_str());

        if (vm.count("mac-address")) {
            std::cout << "Using MAC address: " << vm["mac-address"].as<std::string>() << ".\n";

            if (!parse_mac_address(vm["mac-address"].as<std::string>().c_str(), address)) {
                std::cerr << "The specified MAC address is invalid." << "\n";
                return 1;
            }

            device = new FakeNetworkDevice(*device, address);
        }

        asio::generic::raw_protocol raw_protocol(AF_PACKET, gn::ether_type.net());
        asio::generic::raw_protocol::socket raw_socket(io_service, raw_protocol);
        raw_socket.bind(device->endpoint(AF_PACKET));

        auto signal_handler = [&io_service](const boost::system::error_code& ec, int signal_number) {
            if (!ec) {
                std::cout << "Termination requested." << std::endl;
                io_service.stop();
            }
        };
        asio::signal_set signals(io_service, SIGINT, SIGTERM);
        signals.async_wait(signal_handler);

        TimeTrigger trigger(io_service);
        GpsPositionProvider positioning;
        RouterContext context(raw_socket, *device, trigger, positioning);

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
