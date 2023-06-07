#ifndef TCP_LINK_HPP_A16QFBX3
#define TCP_LINK_HPP_A16QFBX3

#include "link_layer.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>
#include <array>
#include <list>

static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Link, vanetza::OsiLayer::Application);


class TcpSocket
{
public:
    using IndicationCallback = std::function<void(vanetza::CohesivePacket&&, const vanetza::EthernetHeader&)>;

    TcpSocket(boost::asio::io_service&, IndicationCallback&);

    void connect(boost::asio::ip::tcp::endpoint);
    void request(std::array<boost::asio::const_buffer, layers_>);
    void do_receive();

    boost::asio::ip::tcp::socket& socket();
    bool connected();
    void connected(bool);

private:

    bool is_connected_;
    boost::asio::io_service* io_service_;
    boost::asio::ip::tcp::endpoint endpoint_;
    boost::asio::ip::tcp::socket socket_;
    vanetza::ByteBuffer rx_buffer_;
    IndicationCallback* callback_;

};


class TcpLink : public LinkLayer
{
public:
    TcpLink(boost::asio::io_service&);
    ~TcpLink();

    void indicate(IndicationCallback) override;
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;
    void connect(boost::asio::ip::tcp::endpoint);
    void accept(boost::asio::ip::tcp::endpoint);
    void accept_handler(boost::system::error_code& ec, TcpSocket* ts, boost::asio::ip::tcp::endpoint ep);

private:
    std::list<TcpSocket*> sockets_;
    std::map<boost::asio::ip::tcp::endpoint, boost::asio::ip::tcp::acceptor*> acceptors_;
    IndicationCallback callback_;
    boost::asio::io_service* io_service_;
    std::array<vanetza::ByteBuffer, layers_> tx_buffers_;
};



#endif /* TCP_LINK_HPP_A16QFBX3 */

