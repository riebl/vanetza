#include "ethernet_device.hpp"
#include "benchmark_application.hpp"
#include "cam_application.hpp"
//#include "its_lci.hpp"
#include "hello_application.hpp"
#include "link_layer.hpp"
#include "positioning.hpp"
#include "router_context.hpp"
#include "security.hpp"
#include "time_trigger.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <iostream>

#ifdef SOCKTAP_WITH_CUBE_EVK
#include "nfiniity_cube_evk.hpp"
#endif

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
        ("gn-version", po::value<unsigned>()->default_value(1), "GeoNetworking protocol version to use.")
        ("cam-interval", po::value<unsigned>()->default_value(1000), "CAM sending interval in milliseconds.")
        ("print-rx-cam", "Print received CAMs")
        ("print-tx-cam", "Print generated CAMs")
        ("benchmark", "Enable benchmarking")
        ("send-to-server", "Send V2X data to server")
        ("server-ip",po::value<std::string>()->default_value("192.168.1.124"), "Server IP")
        ("server-port", po::value<unsigned>()->default_value(9000), "Server Port")
        ("station-id", po::value<unsigned>()->default_value(1), "Station ID")
        ("applications,a", po::value<std::vector<std::string>>()->default_value({"ca"}, "ca")->multitoken(), "Run applications [ca,de,hello,benchmark]")
        ("non-strict", "Set MIB parameter ItsGnSnDecapResultHandling to NON_STRICT")
    ;
    add_positioning_options(options);
    add_security_options(options);
    add_link_layer_options(options);

#ifdef SOCKTAP_WITH_CUBE_EVK
    nfiniity::add_cube_evk_options(options);
#endif

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

        const std::string link_layer_name = vm["link-layer"].as<std::string>();
        auto link_layer =  create_link_layer(io_service, device, link_layer_name, vm);
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
        if (vm.count("non-strict")) {
            mib.itsGnSnDecapResultHandling = vanetza::geonet::SecurityDecapHandling::Non_Strict;
        }
        mib.itsGnProtocolVersion = vm["gn-version"].as<unsigned>();

        if (mib.itsGnProtocolVersion != 0 && mib.itsGnProtocolVersion != 1) {
            throw std::runtime_error("Unsupported GeoNetworking version, only version 0 and 1 are supported.");
        }

        auto positioning = create_position_provider(io_service, vm, trigger.runtime());
        if (!positioning) {
            std::cerr << "Requested positioning method is not available\n";
            return 1;
        }

        auto security = create_security_entity(vm, trigger.runtime(), *positioning);
        if (security) {
            mib.itsGnSecurity = true;
        }

        RouterContext context(mib, trigger, *positioning, security.get());
        context.require_position_fix(vm.count("require-gnss-fix") > 0);
        context.set_link_layer(link_layer.get());

        std::map<std::string, std::unique_ptr<Application>> apps;
        for (const std::string& app_name : vm["applications"].as<std::vector<std::string>>()) {
            if (apps.find(app_name) != apps.end()) {
                std::cerr << "application '" << app_name << "' requested multiple times, skip\n";
                continue;
            }

            if (app_name == "ca") {
                std::unique_ptr<CamApplication> ca {
                    new CamApplication(*positioning, trigger.runtime())
                };
                ca->set_interval(std::chrono::milliseconds(vm["cam-interval"].as<unsigned>()));
                ca->print_received_message(vm.count("print-rx-cam") > 0);
                ca->print_generated_message(vm.count("print-tx-cam") > 0);
                ca->setStationID(vm["station-id"].as<unsigned>());
                if(vm.count("send-to-server") > 0){
                    ca->setServerIP(vm["server-ip"].as<std::string>().data());
                    ca->setServerPort(vm["server-port"].as<unsigned>());
                    
                    ca->createSocket();
                    ca->setSendToServer(true);
                }
                apps.emplace(app_name, std::move(ca));
            } /*
            else if (app_name == "DE") {
                std::unique_ptr<ITC_LCI_Application> de {
                    new ITC_LCI_Application(*positioning, trigger.runtime())
                };
                //ca->set_interval(std::chrono::milliseconds(vm["cam-interval"].as<unsigned>()));
                //ca->print_received_message(vm.count("print-rx-cam") > 0);
                //ca->print_generated_message(vm.count("print-tx-cam") > 0);
                apps.emplace(app_name, std::move(de));
            }*/ else if (app_name == "hello") {
                std::unique_ptr<HelloApplication> hello {
                    new HelloApplication(io_service, std::chrono::milliseconds(800))
                };
                apps.emplace(app_name, std::move(hello));
            } else if (app_name == "benchmark") {
                std::unique_ptr<BenchmarkApplication> benchmark {
                    new BenchmarkApplication(io_service)
                };
                apps.emplace(app_name, std::move(benchmark));
            } else {
                std::cerr << "skip unknown application '" << app_name << "'\n";
            }
        }

        if (apps.empty()) {
            std::cerr << "Warning: No applications are configured, only GN beacons will be exchanged\n";
        }

        for (const auto& app : apps) {
            std::cout << "Enable application '" << app.first << "'...\n";
            context.enable(app.second.get());
        }

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
