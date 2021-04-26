#ifndef RAW_SOCKET_LINK_HPP_VUXH507U
#define RAW_SOCKET_LINK_HPP_VUXH507U

#include "link_layer.hpp"
#include <vanetza/access/interface.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <boost/optional/optional.hpp>
#include <array>
#include <functional>

class RawSocketLink : public LinkLayer
{
public:
    RawSocketLink(boost::asio::generic::raw_protocol::socket&&);
    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;
    void indicate(IndicationCallback) override;

protected:
    std::size_t transmit(std::unique_ptr<vanetza::ChunkPacket>);
    virtual boost::optional<vanetza::EthernetHeader> parse_ethernet_header(vanetza::CohesivePacket&) const;

private:
    void do_receive();
    void on_read(const boost::system::error_code&, std::size_t);
    void pass_up(vanetza::CohesivePacket&&);

    static constexpr std::size_t layers_ = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);

    boost::asio::generic::raw_protocol::socket socket_;
    std::array<vanetza::ByteBuffer, layers_> buffers_;
    IndicationCallback callback_;
    vanetza::ByteBuffer receive_buffer_;
    boost::asio::generic::raw_protocol::endpoint receive_endpoint_;
};

#endif /* RAW_SOCKET_LINK_HPP_VUXH507U */

