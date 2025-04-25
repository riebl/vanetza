#include <boost/asio/post.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <vanetza/net/osi_layer.hpp>

#include "autotalks_link.hpp"


#define TX_BUFFER_SIZE      2048


AutotalksLink::AutotalksLink(boost::asio::io_context& io, const std::string& endpoint, vanetza::geonet::MIB& mib)
                             : io_(io),
                               autotalksNet_(vanetza::autotalks_net::V2XOperationMode_t::ITS_G5, io, endpoint),
                               mib_(mib)
{
    autotalksNet_.Indicate(std::bind(&AutotalksLink::NetIndicate, this, std::placeholders::_1));
    autotalksNet_.IndicateDcc(std::bind(&AutotalksLink::NetDccIndicate, this, std::placeholders::_1));
    // Address change callback is set later
}

void AutotalksLink::request(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    uint8_t toSend[TX_BUFFER_SIZE];
    size_t j = 0;

    static constexpr std::size_t layers = num_osi_layers(vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application);
    std::array<vanetza::ByteBuffer, layers> buffers;

    for (auto& layer : vanetza::osi_layer_range<vanetza::OsiLayer::Physical, vanetza::OsiLayer::Application>()) {
        const auto index = distance(vanetza::OsiLayer::Physical, layer);
        packet->layer(layer).convert(buffers[index]);

        for (size_t i = 0; i < buffers[index].size() && j < TX_BUFFER_SIZE; i++)
            toSend[j++] = buffers[index][i];
    }
    uint16_t datalen = j;
    autotalksNet_.Transmit(request, (uint8_t*) toSend, datalen, mib_.itsGnIfType);
}

void AutotalksLink::setMac(const std::vector<uint8_t>& addr)
{
    autotalksNet_.SetMac(addr);
}

void AutotalksLink::indicate(IndicationCallback callback)
{
    callback_ = callback;
}

void AutotalksLink::addDccCallback(std::function<void(vanetza::dcc::ChannelLoad)> callback)
{
    cbrCallback_ = callback;
}

void AutotalksLink::DccMeasuredCallback(vanetza::dcc::ChannelLoad cbr)
{
    if (cbrCallback_)
    {
        boost::asio::post(io_, [this, cbr]() mutable
        {
            cbrCallback_(cbr);
        });
    }
}

void AutotalksLink::data_received(const vanetza::autotalks_net::V2xFrame& frame)
{
    vanetza::ByteBuffer buffer(frame.Data.size());
    for (uint16_t i = 0; i < frame.Data.size(); i++)
        buffer[i] = frame.Data[i];
    vanetza::CohesivePacket packet(std::move(buffer), vanetza::OsiLayer::Physical);
    boost::optional<vanetza::EthernetHeader> eth = autotalksNet_.strip_rx_header(packet, frame);
    if (callback_ && eth)
    {
        boost::asio::post(io_, [this, packet = std::move(packet), eth]() mutable
        {
            callback_(std::move(packet), *eth);
        });
    }
}

void AutotalksLink::NetIndicate(const vanetza::autotalks_net::V2xFrame& frame)
{
    data_received(frame);
}

void AutotalksLink::NetDccIndicate(const vanetza::autotalks_net::ChannelBusyRatio& cbr)
{
    // CBR measurement - callback to DCC layer
    uint32_t cbr_value = cbr.Busy;
    vanetza::dcc::ChannelLoad cbrValue = vanetza::UnitInterval(((double) cbr_value) / 100.0);
    DccMeasuredCallback(cbrValue);
}

void AutotalksLink::setAddressChangeCallback(std::function<void(const vanetza::MacAddress&)> callback)
{
    autotalksNet_.IndicateAddressChange(callback);
}
