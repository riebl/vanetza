#include "link_layer.hpp"
#include "raw_socket_link.hpp"
#include "tcp_link.hpp"
#include "udp_link.hpp"
#include <vanetza/access/ethertype.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

#ifdef SOCKTAP_WITH_CUBE_EVK
#   include "nfiniity_cube_evk_link.hpp"
#endif

#ifdef SOCKTAP_WITH_COHDA_LLC
#   include "cohda_link.hpp"
#endif

#ifdef SOCKTAP_WITH_AUTOTALKS
#   include "autotalks_link.hpp"
#   include "autotalks.hpp"
#endif

boost::optional<std::pair<boost::asio::ip::address, unsigned short>> parse_ip_port(const std::string& ip_port)
{
    using opt_ip_port = boost::optional<std::pair<boost::asio::ip::address, unsigned short>>;

    std::size_t ip_len = ip_port.find_last_of(":");
    if (ip_len == std::string::npos) {
        // error: port not found
        std::cerr << "[" << ip_port << "] Missing port." << std::endl;
        return opt_ip_port();
    }

    std::size_t port = std::strtoul(ip_port.substr(ip_len + 1).c_str(), NULL, 10);
    if (port < 1 || port > 65535) {
        // error: port out of range
        std::cerr << "[" << ip_port << "] Port " << port << " out of range (1-65535)." << std::endl;
        return opt_ip_port();
    }

    boost::system::error_code ec;
    boost::asio::ip::address ip = boost::asio::ip::address::from_string(ip_port.substr(0, ip_len), ec);
    if (ec) {
        // error: IP-address invalid
        std::cerr << "[" << ip_port << "] Invalid IP-address: " << ec.message() << std::endl;
        return opt_ip_port();
    }

    return opt_ip_port({ip, port});
}

std::unique_ptr<LinkLayer>
create_link_layer(boost::asio::io_service& io_service, const EthernetDevice& device, const std::string& name, const boost::program_options::variables_map& vm)
{
    std::unique_ptr<LinkLayer> link_layer;

    if (name == "ethernet" || name == "cohda") {
        boost::asio::generic::raw_protocol raw_protocol(AF_PACKET, vanetza::access::ethertype::GeoNetworking.net());
        boost::asio::generic::raw_protocol::socket raw_socket(io_service, raw_protocol);
        raw_socket.bind(device.endpoint(AF_PACKET));

        if (name == "ethernet") {
            link_layer.reset(new RawSocketLink { std::move(raw_socket) });
        } else if (name == "cohda") {
#ifdef SOCKTAP_WITH_COHDA_LLC
            link_layer.reset(new CohdaLink { std::move(raw_socket) });
#endif
        }
    } else if (name == "udp") {
        namespace ip = boost::asio::ip;
        ip::udp::endpoint multicast(ip::address::from_string("239.118.122.97"), 8947);
        link_layer.reset(new UdpLink { io_service, multicast });
    } else if (name == "tcp") {
        namespace ip = boost::asio::ip;

        TcpLink* tcp = new TcpLink { io_service };

        if (vm.count("tcp-connect")) {
            for (const std::string& ip_port : vm["tcp-connect"].as<std::vector<std::string>>()) {
                auto ip_port_pair = parse_ip_port(ip_port);
                if (ip_port_pair.is_initialized()) {
                    tcp->connect(ip::tcp::endpoint(ip_port_pair.value().first, ip_port_pair.value().second));
                }
            }
        }

        if (vm.count("tcp-accept")) {
            for (const std::string& ip_port : vm["tcp-accept"].as<std::vector<std::string>>()) {
                auto ip_port_pair = parse_ip_port(ip_port);
                if (ip_port_pair.is_initialized()) {
                    tcp->accept(ip::tcp::endpoint(ip_port_pair.value().first, ip_port_pair.value().second));
                }
            }
        }

        link_layer.reset(tcp);

    } else if (name == "autotalks") {
#ifdef SOCKTAP_WITH_AUTOTALKS
        link_layer.reset(new AutotalksLink { io_service });
#endif
    } else if (name == "cube-evk") {
#ifdef SOCKTAP_WITH_CUBE_EVK
        link_layer.reset(new CubeEvkLink { io_service, boost::asio::ip::address_v4::from_string(vm["cube-ip"].as<std::string>()) });
#endif
    }

    return link_layer;
}

void add_link_layer_options(boost::program_options::options_description& options)
{
    options.add_options()
        ("tcp-connect", boost::program_options::value<std::vector<std::string>>()->multitoken(), "Connect to TCP-Host(s). Comma separated list of [ip]:[port].")
        ("tcp-accept", boost::program_options::value<std::vector<std::string>>()->multitoken(), "Accept TCP-Connections. Comma separated list of [ip]:[port].")
    ;
}
