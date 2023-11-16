#ifndef CUBE_EVK_LINK_HPP_
#define CUBE_EVK_LINK_HPP_

#include "../raw_socket_link.hpp"
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <vanetza/net/chunk_packet.hpp>

#include <array>
#include <cstdint>
#include <memory>

#include "cube-radio.pb.h"

class CubeEvkLink : public LinkLayer
{
public:
    CubeEvkLink(boost::asio::io_service&, boost::asio::ip::address_v4);

    void handle_packet_received(const boost::system::error_code&, size_t);
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;

    void indicate(IndicationCallback callback) override;

private:
    boost::asio::io_service& io_;
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

#endif /* CUBE_EVK_LINK_HPP_ */

