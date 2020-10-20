#ifndef UDP_LINK_HPP_A16QFBX3
#define UDP_LINK_HPP_A16QFBX3

#include "link_layer.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <array>

class UdpLink : public LinkLayer
{
public:
    UdpLink(boost::asio::io_service&, const boost::asio::ip::udp::endpoint&);

    void indicate(IndicationCallback) override;
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;

private:
    void do_receive();

    static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Link, vanetza::OsiLayer::Application);

    boost::asio::ip::udp::endpoint multicast_endpoint_;
    boost::asio::ip::udp::socket tx_socket_;
    boost::asio::ip::udp::socket rx_socket_;
    std::array<vanetza::ByteBuffer, layers_> tx_buffers_;
    vanetza::ByteBuffer rx_buffer_;
    boost::asio::ip::udp::endpoint rx_endpoint_;
    IndicationCallback callback_;
};

#endif /* UDP_LINK_HPP_A16QFBX3 */

