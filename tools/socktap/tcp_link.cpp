#include "tcp_link.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/asio/write.hpp>
#include <boost/bind/bind.hpp>
#include <boost/bind/placeholders.hpp>
#include <iostream>
#include <utility>

namespace ip = boost::asio::ip;
using namespace vanetza;

TcpLink::TcpLink(boost::asio::io_service& io_service) :
    io_service_(&io_service)
{

}

void TcpLink::indicate(IndicationCallback cb)
{
    callback_ = cb;
    for (auto& ep : waiting_endpoints_) {
        connect(ep);
    }
}

void TcpLink::request(const access::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    // create ethernet header
    vanetza::ByteBuffer buffer = create_ethernet_header(request.destination_addr, request.source_addr, request.ether_type);

    // insert packet size before ethernet header
    uint16_t packet_size = packet->size(OsiLayer::Network, OsiLayer::Application) + EthernetHeader::length_bytes;
    buffer.insert(buffer.begin(), packet_size & 0x00FF);
    buffer.insert(buffer.begin(), (packet_size & 0xFF00) >> 8);

    packet->layer(OsiLayer::Link) = std::move(buffer);

    std::array<boost::asio::const_buffer, layers_> const_buffers;
    for (auto& layer : osi_layer_range<OsiLayer::Link, OsiLayer::Application>()) {
        const auto index = distance(OsiLayer::Link, layer);
        packet->layer(layer).convert(tx_buffers_[index]);
        const_buffers[index] = boost::asio::buffer(tx_buffers_[index]);
    }

    std::list<TcpSocket>::iterator i = sockets_.begin();

    while (i != sockets_.end()) {
        if ((*i).status() == TcpSocket::CONNECTED) {
            (*i).request(const_buffers);
            i++;
        } else if ((*i).status() == TcpSocket::ERROR) {
            sockets_.erase(i++);
            std::cerr << "Socket removed" << std::endl;
        } else {
            i++;
        }
    }
}

void TcpLink::connect(ip::tcp::endpoint ep)
{
    if (callback_) {
        sockets_.emplace_back(*io_service_, &callback_);
        auto& sock = sockets_.back();
        sock.connect(ep);
    } else {
        waiting_endpoints_.push_back(ep);
    }
}

void TcpLink::accept(ip::tcp::endpoint ep)
{
    if (acceptors_.count(ep) == 0) {
        acceptors_.insert(std::make_pair(ep, ip::tcp::acceptor(*io_service_, ep)));
    }

    sockets_.emplace_back(*io_service_, &callback_);
    auto& sock = sockets_.back();
    sock.status(TcpSocket::ACCEPTING);

    boost::system::error_code ec;
    std::cout << "Accept connetions at " << ep.address().to_string() << ":" << ep.port() << std::endl;

    acceptors_.find(ep)->second.async_accept(
        sock.socket(),
        boost::bind(
            &TcpLink::accept_handler,
            this,
            ec,
            ep,
            &sock
        )
    );
}

void TcpLink::accept_handler(boost::system::error_code& ec, ip::tcp::endpoint ep, TcpSocket* sock)
{
    sock->status(TcpSocket::CONNECTED);
    sock->do_receive();
    accept(ep);
}


/**
 * TcpSocket
 */

TcpSocket::TcpSocket(boost::asio::io_service& io_service, IndicationCallback* cb) :
    socket_(io_service),
    callback_(cb),
    rx_buffer_(2560, 0x00)
{
}

void TcpSocket::connect(ip::tcp::endpoint ep)
{
    boost::system::error_code ec;
    socket_.connect(ep, ec);
    if (!ec) {
        status_ = CONNECTED;
        do_receive();
    }
}

void TcpSocket::request(std::array<boost::asio::const_buffer, layers_> const_buffers)
{
    boost::system::error_code ec;
    boost::asio::write(socket_, const_buffers, ec);

    if (ec) {
        status_ = ERROR;
    }
}

void TcpSocket::do_receive()
{
    socket_.async_read_some(
        boost::asio::buffer(rx_buffer_),
        boost::bind(
            &TcpSocket::receive_handler,
            this,
            boost::placeholders::_1,
            boost::placeholders::_2
        )
    );
}

void TcpSocket::receive_handler(boost::system::error_code ec, std::size_t length) {
    if (!ec) {
        status_ = CONNECTED;

        rx_store_.insert(rx_store_.end(), rx_buffer_.begin(), rx_buffer_.begin() + length);

        // While we have enough bytes stored to construct a packet, pass it up
        while (rx_store_.size() >= get_next_packet_size() + 2)
        {
            uint16_t packet_length = get_next_packet_size();
            ByteBuffer packet_buffer(rx_store_.begin() + 2, rx_store_.begin() + 2 + packet_length);
            pass_up(std::move(packet_buffer));
            rx_store_.erase(rx_store_.begin(), rx_store_.begin() + 2 + packet_length);
        }

        do_receive();
    } else {
        status_ = ERROR;
    }
}

void TcpSocket::pass_up(ByteBuffer&& packet_buffer)
{
    CohesivePacket packet(std::move(packet_buffer), OsiLayer::Link);
    if (packet.size(OsiLayer::Link) < EthernetHeader::length_bytes) {
        std::cerr << "Dropped TCP packet too short to contain Ethernet header\n";
    } else {
        packet.set_boundary(OsiLayer::Link, EthernetHeader::length_bytes);
        auto link_range = packet[OsiLayer::Link];
        EthernetHeader eth = decode_ethernet_header(link_range.begin(), link_range.end());
        if (*callback_) {
            (*callback_)(std::move(packet), eth);
        }
    }
}

uint16_t TcpSocket::get_next_packet_size()
{
    if (rx_store_.size() >= 2) {
        return (rx_store_[0] << 8) + rx_store_[1];
    } else {
        return 0;
    }
}
