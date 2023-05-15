#include "link_layer.hpp"
#include "raw_socket_link.hpp"
#include "udp_link.hpp"
#include <vanetza/access/ethertype.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

#ifdef SOCKTAP_WITH_COHDA_LLC
#   include "cohda_link.hpp"
#endif

std::unique_ptr<LinkLayer>
create_link_layer(boost::asio::io_service& io_service, const EthernetDevice& device, const std::string& name)
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
    }
    else if (name.find("udp-io") != std::string::npos ) { //Input-Output Unicast UDP
        namespace ip = boost::asio::ip;
        boost::system::error_code error_code;

        ip::address ip_address = ip::make_address("127.0.0.1", error_code);
        uint16_t udp_port_tx = 8947;
        uint16_t udp_port_rx = udp_port_tx;

        // TODO: It's time to have a configuration file as input.. yalm?
        // Use: -l udp-io:<ip_dest>:<port_tx>:<port_rx>
        std::vector<std::string> udp_unicast_split_data;
        boost::algorithm::split(udp_unicast_split_data, name, boost::is_any_of(":"));
        if(udp_unicast_split_data.size() == 4) {

            auto ip_address_str = udp_unicast_split_data[1];
            ip_address = ip::make_address(ip_address_str, error_code);
            if (error_code)
            {
                auto error = std::string("Error parsing ip when using link-layer udp-io");
                throw std::invalid_argument(error);
            }

            try {
                udp_port_tx = std::stoi(udp_unicast_split_data[2]);
                udp_port_rx = std::stoi(udp_unicast_split_data[3]);

            }catch(...){
                auto error = std::string("Error parsing ports when using link-layer udp-io");
                throw std::invalid_argument(error);
            }
        }

        ip::udp::endpoint unicast_tx(ip_address, udp_port_tx);
        ip::udp::endpoint unicast_rx(ip::address::from_string("0.0.0.0"), udp_port_rx);
        link_layer.reset(new UdpLink{io_service, unicast_tx, unicast_rx});
    }

    return link_layer;
}
