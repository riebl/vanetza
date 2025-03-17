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
    CubeEvkLink(boost::asio::io_context&, boost::asio::ip::address);

    void handle_packet_received(const boost::system::error_code&, size_t);
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;

    void indicate(IndicationCallback callback) override;

private:
    boost::asio::io_context& io_;
    IndicationCallback indicate_to_router_;

    boost::asio::ip::udp::socket tx_socket_;
    boost::asio::ip::udp::socket rx_socket_;
    boost::asio::ip::udp::endpoint host_endpoint_;

    std::array<uint8_t, 4096> received_data_;

    static constexpr unsigned int cube_evk_radio_port_tx = 33210;
    static constexpr unsigned int cube_evk_radio_port_rx = 33211;

    void pass_message_to_router(std::unique_ptr<LinkLayerReception>);
    std::unique_ptr<LinkLayerTransmission> create_link_layer_tx(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>);
};

#endif /* NFINIITY_CUBE_EVK_LINK_HPP_ */

