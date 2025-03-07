#include "autotalks_link.hpp"
#include "autotalks.hpp"
#include <vanetza/net/osi_layer.hpp>

const unsigned SendBufferSize = 2000;

AutotalksLink::AutotalksLink(boost::asio::io_context& io) : io_(io)
{
    vanetza::autotalks::autotalks_device_init();
    vanetza::autotalks::init_rx(this);
}

AutotalksLink::~AutotalksLink(void)
{
    vanetza::autotalks::autotalks_device_deinit();
}

void AutotalksLink::request(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    uint8_t toSend[SendBufferSize];
    size_t j = 0;

    constexpr std::size_t layers = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);
    std::array<boost::asio::const_buffer, layers> const_buffers;
    for (auto& layer : vanetza::osi_layer_range<vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application>()) {
        const auto index = distance(vanetza::OsiLayer::Physical, layer);
        packet->layer(layer).convert(buffers_[index]);
        const_buffers[index] = boost::asio::buffer(buffers_[index]);

        for (size_t i = 0; i < buffers_[index].size() && j < SendBufferSize; i++)
            toSend[j++] = buffers_[index][i];
    }

    uint16_t datalen = j;
    vanetza::autotalks::insert_autotalks_header_transmit(request, packet, (uint8_t*) toSend, datalen);
}

void AutotalksLink::data_received(uint8_t* pBuf, uint16_t size, v2x_receive_params_t rx_params)
{
    vanetza::ByteBuffer buffer(size);
    for (uint16_t i = 0; i < size; i++)
        buffer[i] = pBuf[i];
    vanetza::CohesivePacket packet(std::move(buffer), vanetza::OsiLayer::Physical);
    boost::optional<vanetza::EthernetHeader> eth = vanetza::autotalks::strip_autotalks_rx_header(packet, rx_params);
    if (callback_ && eth)
    {
        boost::asio::post(io_, [this, packet = std::move(packet), eth]() mutable
        {
            callback_(std::move(packet), *eth);
        });
    }
}

void AutotalksLink::indicate(IndicationCallback cb)
{
    callback_ = cb;
}
