#ifndef UPPERTESTER_PASSTHROUGH_HPP
#define UPPERTESTER_PASSTHROUGH_HPP

#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

class Passthrough : public vanetza::dcc::RequestInterface
{
public:
    Passthrough(boost::asio::generic::raw_protocol::socket& socket);

    void request(const vanetza::dcc::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet);

private:
    static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);
    boost::asio::generic::raw_protocol::socket& socket;
    std::array<vanetza::ByteBuffer, layers_> buffers;
};

#endif /* UPPERTESTER_PASSTHROUGH_HPP */
