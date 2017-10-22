#ifndef DCC_PASSTHROUGH_HPP_GSDFESAE
#define DCC_PASSTHROUGH_HPP_GSDFESAE

#include "time_trigger.hpp"
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

namespace asio = boost::asio;
using boost::asio::generic::raw_protocol;
using namespace vanetza;

class DccPassthrough : public dcc::RequestInterface
{
public:
    DccPassthrough(raw_protocol::socket& socket, TimeTrigger& trigger);

    void request(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket> packet);

    void allow_packet_flow(bool allow);

    bool allow_packet_flow();

private:
    static constexpr std::size_t layers_ = num_osi_layers(OsiLayer::Link, OsiLayer::Application);
    raw_protocol::socket& socket_;
    std::array<ByteBuffer, layers_> buffers_;
    TimeTrigger& trigger_;
    bool allow_packet_flow_ = true;
};

#endif /* DCC_PASSTHROUGH_HPP_GSDFESAE */
