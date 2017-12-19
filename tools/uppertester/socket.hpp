#ifndef UPPERTESTER_SOCKET_HPP
#define UPPERTESTER_SOCKET_HPP

#include <boost/asio.hpp>
#include <vanetza/btp/port_dispatcher.hpp>
#include <vanetza/common/byte_buffer.hpp>

class UpperTester;

class Socket
{
    const static uint MAX_LENGTH = 65535;

public:
    Socket(UpperTester& app, boost::asio::io_service& io_service, uint16_t port);

    void handle_receive_from(const boost::system::error_code& error, std::size_t bytes_recvd);

    void send(const vanetza::ByteBuffer& payload);

private:
    UpperTester& tester;
    vanetza::btp::PortDispatcher dispatcher;
    boost::asio::io_service& io_service;
    boost::asio::ip::udp::socket socket;
    boost::asio::ip::udp::endpoint endpoint;
    char buffer[MAX_LENGTH];
};

#endif /* UPPERTESTER_SOCKET_HPP */
