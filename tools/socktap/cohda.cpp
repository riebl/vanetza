#include "cohda.hpp"
#include <vanetza/access/access_category.hpp>
#include <vanetza/access/g5_link_layer.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <vanetza/dcc/mapping.hpp>
#include <cassert>
#include <llc-api.h>

namespace vanetza
{

void insert_cohda_tx_header(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket>& packet)
{
    access::G5LinkLayer link_layer;
    access::ieee802::dot11::QosDataHeader& mac_header = link_layer.mac_header;
    mac_header.destination = request.destination;
    mac_header.source = request.source;
    mac_header.qos_control.user_priority(dcc::map_profile_onto_ac(request.dcc_profile));

    ByteBuffer link_layer_buffer;
    serialize_into_buffer(link_layer, link_layer_buffer);
    assert(link_layer_buffer.size() == access::G5LinkLayer::length_bytes);
    packet->layer(OsiLayer::Link) = std::move(link_layer_buffer);

    const std::size_t payload_size = packet->size();
    const std::size_t total_size = sizeof(tMKxTxPacket) + payload_size;

    tMKxTxPacket phy = { 0 };
    phy.Hdr.Type = MKXIF_TXPACKET;
    phy.Hdr.Len = total_size;
    phy.TxPacketData.TxAntenna = MKX_ANT_DEFAULT;
    phy.TxPacketData.TxFrameLength = payload_size;
    auto phy_ptr = reinterpret_cast<const uint8_t*>(&phy);
    packet->layer(OsiLayer::Physical) = std::move(ByteBuffer(phy_ptr, phy_ptr + sizeof(tMKxTxPacket)));
}

boost::optional<EthernetHeader> strip_cohda_rx_header(CohesivePacket& packet)
{
    static const std::size_t min_length = sizeof(tMKxRxPacket) + access::G5LinkLayer::length_bytes +
        access::ieee802::dot11::fcs_length_bytes;
    if (packet.size(OsiLayer::Physical) < min_length) {
        return boost::none;
    }

    packet.set_boundary(OsiLayer::Physical, sizeof(tMKxRxPacket));
    auto phy = reinterpret_cast<const tMKxRxPacket*>(&*packet[OsiLayer::Physical].begin());
    if (phy->Hdr.Type != MKXIF_RXPACKET) {
        return boost::none;
    }

    // Sanity check that sizes reported by Cohda LLC are correct, since we rely on Cohda's FCS checking
    if (phy->Hdr.Len != packet.size() || phy->RxPacketData.RxFrameLength != packet.size() - sizeof(tMKxRxPacket)) {
        return boost::none;
    }

    if (!phy->RxPacketData.FCSPass) {
        return boost::none;
    }

    packet.trim(OsiLayer::Link, packet.size() - access::ieee802::dot11::fcs_length_bytes);
    packet.set_boundary(OsiLayer::Link, access::G5LinkLayer::length_bytes);
    access::G5LinkLayer link_layer;
    deserialize_from_range(link_layer, packet[OsiLayer::Link]);
    if (!access::check_fixed_fields(link_layer)) {
        return boost::none;
    }

    EthernetHeader eth;
    eth.destination = link_layer.mac_header.destination;
    eth.source = link_layer.mac_header.source;
    eth.type = link_layer.llc_snap_header.protocol_id;
    return eth;
}

} // namespace vanetza
