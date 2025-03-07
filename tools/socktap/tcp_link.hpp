#ifndef TCP_LINK_HPP_A16QFBX3
#define TCP_LINK_HPP_A16QFBX3

#include "link_layer.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <array>
#include <list>

static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);


class TcpSocket
{
public:
    enum Status
    {
        UNDEFINED = 0,
        CONNECTED = 1,
        ACCEPTING = 2,
        ERROR = 3
    };

    using IndicationCallback = std::function<void(vanetza::CohesivePacket&&, const vanetza::EthernetHeader&)>;

    TcpSocket(boost::asio::io_context&, IndicationCallback*);

    void connect(boost::asio::ip::tcp::endpoint);
    void request(std::array<boost::asio::const_buffer, layers_>);
    void do_receive();
    void receive_handler(boost::system::error_code, std::size_t);
    uint16_t get_next_packet_size();
    void pass_up(vanetza::ByteBuffer&&);

    boost::asio::ip::tcp::socket& socket() { return socket_; }

    Status status() { return status_; }
    void status(Status s) { status_ = s; }

private:
    Status status_ = UNDEFINED;
    boost::asio::io_context* io_context_;
    boost::asio::ip::tcp::endpoint endpoint_;
    boost::asio::ip::tcp::socket socket_;
    vanetza::ByteBuffer rx_buffer_;
    vanetza::ByteBuffer rx_store_;
    IndicationCallback* callback_;

};


class TcpLink : public LinkLayer
{
public:
    TcpLink(boost::asio::io_context&);

    void indicate(IndicationCallback) override;
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;
    void connect(boost::asio::ip::tcp::endpoint);
    void accept(boost::asio::ip::tcp::endpoint);
    void accept_handler(boost::system::error_code& ec, boost::asio::ip::tcp::endpoint ep, TcpSocket* sock);

private:
    std::list<TcpSocket> sockets_;
    std::map<boost::asio::ip::tcp::endpoint, boost::asio::ip::tcp::acceptor> acceptors_;
    IndicationCallback callback_;
    boost::asio::io_context* io_context_;
    std::array<vanetza::ByteBuffer, layers_> tx_buffers_;
    std::list<boost::asio::ip::tcp::endpoint> waiting_endpoints_;
};


#endif /* TCP_LINK_HPP_A16QFBX3 */

