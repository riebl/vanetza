#include "ethernet_device.hpp"
#include "hello_application.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>
#include "FirstEthernetInterface.hpp"


namespace asio = boost::asio;
namespace gn = vanetza::geonet;
using namespace vanetza;


int main(int argc, const char** argv)
{
	const char* device_name;
	std::string interfaceType;
	std::string filePathFromTerminal = "";
	CGpsData dummyGPSObj;

	// if terminal command is just ./socktap
	if (argc == 1) 
	{		
		 //get first ethernet device and assignin it to device_name 
		device_name = getFirstEthernetDeviceName();
		std::cout << "Will use 1st ethernet device: " << device_name << " and GPS dongle" << std::endl;
		
	      /*
	       * Code for GPS integration will be added once GPS dongle is procured
	       */
	} 
	else
	{
		interfaceType = argv[1];

		if (interfaceType == "-I")
		{
			device_name = argv[2];
			std::cout << "Will use ethernet device:" << argv[2] << " and GPS dongle"
					<< std::endl;
			
		}
		if (interfaceType == "-F") 
		{
			device_name = getFirstEthernetDeviceName();
			std::cout << "Will use 1st ethernet device: " << device_name <<" and nmea text from location: " << argv[2]
					<< std::endl;
			filePathFromTerminal = argv[2];			
		}
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

	dummyGPSObj.filePathFromTerminal = filePathFromTerminal;	
	
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
