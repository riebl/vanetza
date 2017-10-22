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

class DccPassthrough : public dcc::RequestInterface
{
public:
    DccPassthrough(raw_protocol::socket& socket, TimeTrigger& trigger) :
        socket_(socket), trigger_(trigger) {}

    void request(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
    {
        if (!allow_packet_flow_) {
            std::cout << "ignored request because packet flow is suppressed\n";
            return;
        }

        buffers_[0] = create_ethernet_header(request.destination, request.source, request.ether_type);
        for (auto& layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
            const auto index = distance(OsiLayer::Link, layer);
            packet->layer(layer).convert(buffers_[index]);
        }

        trigger_.schedule();

        std::array<asio::const_buffer, layers_> const_buffers;
        for (unsigned i = 0; i < const_buffers.size(); ++i) {
            const_buffers[i] = asio::buffer(buffers_[i]);
        }
        auto bytes_sent = socket_.send(const_buffers);
        std::cout << "sent packet to " << request.destination << " (" << bytes_sent << " bytes)\n";
    }

    void allow_packet_flow(bool allow)
    {
        allow_packet_flow_ = allow;
    }

    bool allow_packet_flow()
    {
        return allow_packet_flow_;
    }

private:
    static constexpr std::size_t layers_ = num_osi_layers(OsiLayer::Link, OsiLayer::Application);
    raw_protocol::socket& socket_;
    std::array<ByteBuffer, layers_> buffers_;
    TimeTrigger& trigger_;
    bool allow_packet_flow_ = true;
};
