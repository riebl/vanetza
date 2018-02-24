#include "socket.hpp"
#include "uppertester.hpp"
#include <boost/bind.hpp>
#include <boost/algorithm/hex.hpp>
#include <iostream>

using namespace vanetza;
using namespace boost::asio::ip;

Socket::Socket(UpperTester& tester, boost::asio::io_service& io_service, uint16_t port)
    : tester(tester), io_service(io_service), socket(io_service, udp::endpoint(udp::v4(), port))
{
    tester.socket = this;

    socket.async_receive_from(
        boost::asio::buffer(buffer, MAX_LENGTH),
        endpoint,
        boost::bind(&Socket::handle_receive_from, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
    );
}

void Socket::handle_receive_from(const boost::system::error_code& error, std::size_t bytes_recvd)
{
    if (error) {
        return;
    }

    std::cout << "Received a packet with " << bytes_recvd << " bytes." << std::endl;

    ByteBuffer packet(buffer, buffer + bytes_recvd);
    tester.process_udp_trigger(packet);

    socket.async_receive_from(
        boost::asio::buffer(buffer, MAX_LENGTH),
        endpoint,
        boost::bind(&Socket::handle_receive_from, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)
    );
}

void Socket::send(const ByteBuffer& payload)
{
    char buffer[payload.size()];
    std::copy(payload.begin(), payload.end(), buffer);

    std::cout << "Sending packet: ";
    boost::algorithm::hex(payload.begin(), payload.end(), std::ostream_iterator<char>(std::cout));
    std::cout << " (" << payload.size() << " bytes)" << std::endl;

    // Don't bother with sending things async in this application, no need for the additional complexity
    socket.send_to(boost::asio::buffer(buffer, payload.size()), endpoint);
}
