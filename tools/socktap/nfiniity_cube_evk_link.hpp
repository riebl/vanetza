#ifndef NFINIITY_CUBE_EVK_LINK_HPP_
#define NFINIITY_CUBE_EVK_LINK_HPP_

#include "link_layer.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <vanetza/net/chunk_packet.hpp>

#include <array>
#include <cstdint>
#include <memory>

class LinkLayerReception;
class LinkLayerTransmission;

class CubeEvkLink : public LinkLayer
{
public:
    using Endpoint = boost::asio::ip::udp::endpoint;
    CubeEvkLink(boost::asio::io_context&, const Endpoint& tx, const Endpoint& rx);

    void handle_packet_received(const boost::system::error_code&, size_t);
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;

    void indicate(IndicationCallback callback) override;

    static constexpr unsigned default_tx_port = 33210;
    static constexpr unsigned default_rx_port = 33211;

private:
    boost::asio::io_context& io_;
    IndicationCallback indicate_to_router_;

    boost::asio::ip::udp::socket tx_socket_;
    boost::asio::ip::udp::socket rx_socket_;
    boost::asio::ip::udp::endpoint host_endpoint_;

    std::array<uint8_t, 4096> received_data_;

    void pass_message_to_router(std::unique_ptr<LinkLayerReception>);
    std::unique_ptr<LinkLayerTransmission> create_link_layer_tx(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>);
};

#endif /* NFINIITY_CUBE_EVK_LINK_HPP_ */

