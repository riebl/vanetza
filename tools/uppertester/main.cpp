#include "ethernet_device.hpp"
#include "socket.hpp"
#include "uppertester.hpp"
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/program_options.hpp>
#include <vanetza/common/runtime.hpp>
#include <cstdint>
#include <iostream>

namespace po = boost::program_options;
namespace asio = boost::asio;
using namespace vanetza;

int main(int argc, const char** argv)
{
    po::options_description options("options");
    options.add_options()
        ("port", po::value<uint16_t>()->default_value(5000), "UDP port to receive messages on.")
        ("interface,i", po::value<std::string>()->default_value("lo"), "Network interface to use.")
    ;

    po::variables_map vm;

    po::parsed_options parsed = po::command_line_parser(argc, argv)
        .options(options)
        .run();

    po::store(parsed, vm);
    po::notify(vm);

    uint16_t port = vm["port"].as<uint16_t>();

    std::cerr << "Listening on port " << port << " for UDP packets." << std::endl;

    try {
        asio::io_service io_service;

        const char* device_name = vm["interface"].as<std::string>().c_str();
        EthernetDevice device(device_name);

        geonet::MIB mib;
        mib.itsGnLocalGnAddr.mid(device.address());
        mib.itsGnLocalGnAddr.is_manually_configured(true);
        mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::MANAGED;

        asio::generic::raw_protocol raw_protocol(AF_PACKET, geonet::ether_type.net());
        asio::generic::raw_protocol::socket raw_socket(io_service, raw_protocol);
        asio::socket_base::do_not_route do_not_route;
        raw_socket.set_option(do_not_route);
        raw_socket.bind(device.endpoint(AF_PACKET));

        TimeTrigger trigger(io_service);
        UpperTester tester(raw_socket, trigger, mib);
        Socket socket(tester, io_service, port);

        auto signal_handler = [&io_service](const boost::system::error_code& ec, int signal_number) {
            if (!ec) {
                std::cout << "Termination requested." << std::endl;
                io_service.stop();
            }
        };

        asio::signal_set signals(io_service, SIGINT, SIGTERM);
        signals.async_wait(signal_handler);

        io_service.run();
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;

        return 1;
    }

    return 0;
}
