#include "ethernet_device.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

namespace asio = boost::asio;
namespace gn = vanetza::geonet;
using namespace vanetza;

int main(int argc, const char** argv)
{
    const char* device_name = "lo";
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <device_name>\n";
        return 0;
    } else {
        device_name = argv[1];
    }

    try {
        asio::io_service io_service;
        EthernetDevice device(device_name);
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

        TimeTrigger trigger(io_service);
        RouterContext context(raw_socket, device, trigger);

        io_service.run();
    } catch (std::exception& e) {
        std::cerr << "Exit with error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
