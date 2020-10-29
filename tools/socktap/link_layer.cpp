#include "link_layer.hpp"
#include "raw_socket_link.hpp"
#include "udp_link.hpp"
#include <vanetza/access/ethertype.hpp>
#include <boost/asio/generic/raw_protocol.hpp>

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

    return link_layer;
}
