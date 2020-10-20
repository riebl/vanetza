#include "udp_link.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/asio/ip/multicast.hpp>
#include <iostream>

namespace ip = boost::asio::ip;
using namespace vanetza;

UdpLink::UdpLink(boost::asio::io_service& io_service, const ip::udp::endpoint& endpoint) :
    multicast_endpoint_(endpoint),
    tx_socket_(io_service), rx_socket_(io_service),
    rx_buffer_(2560, 0x00)
{
    tx_socket_.open(multicast_endpoint_.protocol());

    rx_socket_.open(multicast_endpoint_.protocol());
    rx_socket_.set_option(ip::udp::socket::reuse_address(true));
    rx_socket_.bind(multicast_endpoint_);
    rx_socket_.set_option(ip::multicast::enable_loopback(false));
    rx_socket_.set_option(ip::multicast::join_group(multicast_endpoint_.address()));

    do_receive();
}

void UdpLink::indicate(IndicationCallback cb)
{
    callback_ = cb;
}

void UdpLink::do_receive()
{
    rx_socket_.async_receive_from(boost::asio::buffer(rx_buffer_), rx_endpoint_,
            [this](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    ByteBuffer buffer(rx_buffer_.begin(), rx_buffer_.begin() + length);
                    CohesivePacket packet(std::move(buffer), OsiLayer::Link);
                    if (packet.size(OsiLayer::Link) < EthernetHeader::length_bytes) {
                        std::cerr << "Dropped UDP packet too short to contain Ethernet header\n";
                    } else {
                        packet.set_boundary(OsiLayer::Link, EthernetHeader::length_bytes);
                        auto link_range = packet[OsiLayer::Link];
                        EthernetHeader eth = decode_ethernet_header(link_range.begin(), link_range.end());
                        if (callback_) {
                            callback_(std::move(packet), eth);
                        }
                    }
                    do_receive();
                }
            });
}

void UdpLink::request(const access::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    packet->layer(OsiLayer::Link) = create_ethernet_header(request.destination_addr, request.source_addr, request.ether_type);

    std::array<boost::asio::const_buffer, layers_> const_buffers;
    for (auto& layer : osi_layer_range<OsiLayer::Link, OsiLayer::Application>()) {
        const auto index = distance(OsiLayer::Link, layer);
        packet->layer(layer).convert(tx_buffers_[index]);
        const_buffers[index] = boost::asio::buffer(tx_buffers_[index]);
    }

    tx_socket_.send_to(const_buffers, multicast_endpoint_);
}
