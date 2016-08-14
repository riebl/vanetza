#include "ethernet_device.hpp"
#include "hello_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>
#include "NetworkInterface.hpp"
#include <fstream>

namespace asio = boost::asio;
namespace gn = vanetza::geonet;
using namespace vanetza;


int main(int argc, const char** argv) {
	const char* device_name;
	std::string interfaceType;
	std::string filePathFromTerminal = "";
	bool liveGPS = true;
		
	// if terminal command is just ./socktap
	switch (argc) {
	case 1:
		//get first ethernet device and assignin it to device_name 
		device_name = getFirstEthernetDeviceName();
		std::cout << "Will use 1st ethernet device: " << device_name
				<< " and live GPS data" << std::endl;
		break;

	case 3:
		interfaceType = argv[1];

			if (interfaceType == "-I") {
			device_name = argv[2];
			bool status;
			status = NIC(device_name);
			if (!status) {
				std::cout << "Network Interface : " << device_name
						<< " is not found on this system." << std::endl;
				exit(0);
			} else
				std::cout << "Will use ethernet device:" << device_name
						<< " and live GPS data" << std::endl;
		} else if (interfaceType == "-F") {
			filePathFromTerminal = argv[2];
			liveGPS = false;
			device_name = getFirstEthernetDeviceName();
			//device_name = "enp3s0";
			std::fstream file(filePathFromTerminal);
			if (!file.good()) {
				std::cout << "The file specified in the location : "
						<< filePathFromTerminal << " does not exist."
						<< std::endl;
				std::cout << "Ensure that you have not entered the name of an ethernet device." << std::endl;
				std::cout << "If you are entering a file name, make sure it is entered with .txt extenstion" << std::endl;
				
				exit(0);
			} 
			else
			{
				std::cout << "Socktap will use 1st ethernet device: " << device_name
						<< " and nmea text from location: "
						<< filePathFromTerminal << std::endl << std::endl;
			}
		} else {
			std::cout
					<< "Wrong interfaceType chosen. Please choose -F for fake data and -I to select Network Interface Card"
					<< std::endl;
			exit(0);
		}
		break;
	default:
		std::cout << std::endl
				<< "Wrong usage of parameters for running socktap." << std::endl
				<< std::endl;
		std::cout << "Usage:" << std::endl << "./socktap [Interface] [Source]"
				<< std::endl;
		std::cout << "Interface types : " << "\t \t" << "Souce Types:"
				<< std::endl << std::endl;
		std::cout << "-I : Network Interface" << "\t \t"
				<< "Name of network interface on PC. ex-> eth0." << std::endl;
		std::cout << "-F : Fake data source" << "\t \t"
				<< "NMEA sentences stored in text file" << std::endl
				<< std::endl;
		exit(0);
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

        asio::steady_timer hello_timer(io_service);
        HelloApplication hello_app(hello_timer);
        context.enable(&hello_app);

        io_service.run();
    } catch (std::exception& e) {
        std::cerr << "Exit with error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
