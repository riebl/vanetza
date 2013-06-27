#include "telnet_client.h"
#include <cassert>
#include <string>
#include <boost/array.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <boost/lexical_cast.hpp>

namespace asio = boost::asio;
using namespace boost::asio::ip;

TelnetClient::TelnetClient(tcp::socket&& socket) :
    m_socket(std::move(socket)), m_lineend("\r\n")
{
    assert(m_socket.is_open());
}

void TelnetClient::send(const std::string& msg)
{
    boost::array<asio::const_buffer, 2> buffer = {
        asio::buffer(msg),
        asio::buffer(m_lineend) };
    asio::write(m_socket, buffer);
}

TelnetClient connectTelnet(asio::io_service& io, const char* host, unsigned port)
{
    auto service = boost::lexical_cast<std::string>(port);
    tcp::resolver resolver(io);
    tcp::resolver::query query(host, service, resolver_query_base::numeric_service);
    tcp::resolver::iterator iterator = resolver.resolve(query);

    tcp::socket socket(io);
    asio::connect(socket, iterator);

    return TelnetClient(std::move(socket));
}
