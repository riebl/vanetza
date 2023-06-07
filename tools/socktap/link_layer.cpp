#include "link_layer.hpp"
#include "raw_socket_link.hpp"
#include "tcp_link.hpp"
#include "udp_link.hpp"
#include <vanetza/access/ethertype.hpp>
#include <boost/asio/generic/raw_protocol.hpp>

#ifdef SOCKTAP_WITH_COHDA_LLC
#   include "cohda_link.hpp"
#endif

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
    } else if (name.substr(0, 3) == "tcp") {
        namespace ip = boost::asio::ip;

        TcpLink* tcp = new TcpLink { io_service };

        std::string tcp_ip;
        unsigned short tcp_port, tcp_ip_len;

        if (vm.count("tcp-connect")) {
            for (const std::string& ip_port : vm["tcp-connect"].as<std::vector<std::string>>()) {
                tcp_ip_len = ip_port.find(":");
                tcp_ip = ip_port.substr(0, tcp_ip_len);
                tcp_port = std::stoi(ip_port.substr(tcp_ip_len + 1));                
                tcp->connect({ip::address::from_string(tcp_ip), tcp_port});
            }
        }

        if (vm.count("tcp-accept")) {
            for (const std::string& ip_port : vm["tcp-accept"].as<std::vector<std::string>>()) {
                tcp_ip_len = ip_port.find(":");
                tcp_ip = ip_port.substr(0, tcp_ip_len);
                tcp_port = std::stoi(ip_port.substr(tcp_ip_len + 1));
                tcp->accept({ip::address::from_string(tcp_ip), tcp_port});
            }
        }

        link_layer.reset(tcp);

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
