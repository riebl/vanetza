#ifndef TELNETCLIENT_HPP_LMSSEL3Y
#define TELNETCLIENT_HPP_LMSSEL3Y

#include <string>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace vanetza
{

class TelnetClient
{
    public:
    TelnetClient(boost::asio::ip::tcp::socket&&);
    void send(const std::string& msg);

    private:
    boost::asio::ip::tcp::socket m_socket;
    std::string m_lineend;
};

TelnetClient connectTelnet(boost::asio::io_service&, const char* host, unsigned port);

} // namespace vanetza

#endif /* TELNETCLIENT_HPP_LMSSEL3Y */

