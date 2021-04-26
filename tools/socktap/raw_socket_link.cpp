#include "raw_socket_link.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <iostream>

using namespace vanetza;

RawSocketLink::RawSocketLink(boost::asio::generic::raw_protocol::socket&& socket) :
    socket_(std::move(socket)), receive_buffer_(2048, 0x00),
    receive_endpoint_(socket_.local_endpoint())
{
    do_receive();
}

void RawSocketLink::request(const access::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    packet->layer(OsiLayer::Link) = create_ethernet_header(request.destination_addr, request.source_addr, request.ether_type);
    transmit(std::move(packet));
}

std::size_t RawSocketLink::transmit(std::unique_ptr<ChunkPacket> packet)
{
    std::array<boost::asio::const_buffer, layers_> const_buffers;
    for (auto& layer : osi_layer_range<OsiLayer::Physical, OsiLayer::Application>()) {
        const auto index = distance(OsiLayer::Physical, layer);
        packet->layer(layer).convert(buffers_[index]);
        const_buffers[index] = boost::asio::buffer(buffers_[index]);
    }

    return socket_.send(const_buffers);
}

void RawSocketLink::indicate(IndicationCallback callback)
{
    callback_ = callback;
}

void RawSocketLink::do_receive()
{
    namespace sph = std::placeholders;
    socket_.async_receive_from(
            boost::asio::buffer(receive_buffer_), receive_endpoint_,
            std::bind(&RawSocketLink::on_read, this, sph::_1, sph::_2));
}

void RawSocketLink::on_read(const boost::system::error_code& ec, std::size_t read_bytes)
{
    if (!ec) {
        ByteBuffer buffer(receive_buffer_.begin(), receive_buffer_.begin() + read_bytes);
        CohesivePacket packet(std::move(buffer), OsiLayer::Physical);
        boost::optional<EthernetHeader> eth = parse_ethernet_header(packet);
        if (callback_ && eth) {
            callback_(std::move(packet), *eth);
        }
        do_receive();
    }
}

boost::optional<EthernetHeader> RawSocketLink::parse_ethernet_header(vanetza::CohesivePacket& packet) const
{
    packet.set_boundary(OsiLayer::Physical, 0);
    if (packet.size(OsiLayer::Link) < EthernetHeader::length_bytes) {
        std::cerr << "Router dropped invalid packet (too short for Ethernet header)\n";
    } else {
        packet.set_boundary(OsiLayer::Link, EthernetHeader::length_bytes);
        auto link_range = packet[OsiLayer::Link];
        return decode_ethernet_header(link_range.begin(), link_range.end());
    }

    return boost::none;
}
