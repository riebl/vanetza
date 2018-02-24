#include "passthrough.hpp"
#include "time_trigger.hpp"
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

namespace asio = boost::asio;
using boost::asio::generic::raw_protocol;
using namespace vanetza;

Passthrough::Passthrough(raw_protocol::socket& socket) : socket(socket) { }

void Passthrough::request(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    buffers[1] = create_ethernet_header(request.destination, request.source, request.ether_type);
    for (auto& layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
        const auto index = distance(OsiLayer::Physical, layer);
        packet->layer(layer).convert(buffers[index]);
    }

    std::array<asio::const_buffer, layers_> const_buffers;
    for (unsigned i = 0; i < const_buffers.size(); ++i) {
        const_buffers[i] = asio::buffer(buffers[i]);
    }

    std::cout << "Sending packet to " << request.destination << std::endl;
    auto bytes_sent = socket.send(const_buffers);
    std::cout << "Sent packet to " << request.destination << " (" << bytes_sent << " bytes)" << std::endl;
}
