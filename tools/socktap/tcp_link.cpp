#include "tcp_link.hpp"
#include <vanetza/access/data_request.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/bind/bind.hpp>
#include <iostream>

namespace ip = boost::asio::ip;
using namespace vanetza;

TcpLink::TcpLink(boost::asio::io_service& io_service) :
    io_service_(&io_service)
{

}

void TcpLink::indicate(IndicationCallback cb)
{
    callback_ = cb;
}

void TcpLink::request(const access::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    packet->layer(OsiLayer::Link) = create_ethernet_header(request.destination_addr, request.source_addr, request.ether_type);

    std::array<boost::asio::const_buffer, layers_> const_buffers;
    for (auto& layer : osi_layer_range<OsiLayer::Link, OsiLayer::Application>()) {
        const auto index = distance(OsiLayer::Link, layer);
        packet->layer(layer).convert(tx_buffers_[index]);
        const_buffers[index] = boost::asio::buffer(tx_buffers_[index]);
    }

    std::list<TcpSocket>::iterator i = sockets_.begin();

    while (i != sockets_.end()) {
        if ((*i).connected()) {
            (*i).request(const_buffers);
            i++;
        } else {
            sockets_.erase(i++);
            std::cerr << "Socket removed" << std::endl;
        }
    }
}

void TcpLink::connect(ip::tcp::endpoint ep)
{
    TcpSocket ts(*io_service_, callback_);
    ts.connect(ep);
    sockets_.push_back(std::move(ts));
}

void TcpLink::accept(ip::tcp::endpoint ep)
{

    if (acceptors_.count(ep) == 0) {
        acceptors_.find(ep)->second = ip::tcp::acceptor(*io_service_, ep);
    }

    TcpSocket ts(*io_service_, callback_);
    boost::system::error_code ec;
    std::cout << "Accept connetions at " << ep.address().to_string() << ":" << ep.port() << std::endl;

    acceptors_.find(ep)->second.async_accept(
        ts.socket(),
        boost::bind(
            &TcpLink::accept_handler,
            this,
            ec,
            boost::ref(ts),
            ep
        )
    );

}

void TcpLink::accept_handler(boost::system::error_code& ec, TcpSocket& ts, ip::tcp::endpoint ep)
{
    sockets_.push_back(std::move(ts));
    ts.do_receive();
    ts.connected(true);
    accept(ep);
}


/**
 * TcpSocket
 */

TcpSocket::TcpSocket(boost::asio::io_service& io_service, IndicationCallback& cb) :
    socket_(io_service),
    callback_(&cb),
    rx_buffer_(2560, 0x00)
{

}

void TcpSocket::connect(ip::tcp::endpoint ep)
{
    boost::system::error_code ec;
    socket_.connect(ep, ec);
    if (!ec) {
        is_connected_ = true;
        do_receive();
    }

}

void TcpSocket::request(std::array<boost::asio::const_buffer, layers_> const_buffers)
{
    boost::system::error_code ec;
    socket_.write_some(const_buffers, ec);

    if (ec) {
        is_connected_ = false;
    }
}

void TcpSocket::do_receive()
{
    socket_.async_read_some(boost::asio::buffer(rx_buffer_),
        [this](boost::system::error_code ec, std::size_t length) {
            if (!ec) {
                is_connected_ = true;
                ByteBuffer buffer(rx_buffer_.begin(), rx_buffer_.begin() + length);
                CohesivePacket packet(std::move(buffer), OsiLayer::Link);
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
                do_receive();
            } else {
                is_connected_ = false;
            }
        });

}

ip::tcp::socket& TcpSocket::socket()
{
    return socket_;
}

bool TcpSocket::connected()
{
    return is_connected_;
}

void TcpSocket::connected(bool b)
{
    is_connected_ = b;
}

