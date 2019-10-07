#include "cohda.hpp"
#include <llc-api.h>
#include <vanetza/access/g5_link_layer.hpp>
#include <vanetza/dcc/profile.hpp>

namespace vanetza {

void insert_cohda_tx_header(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket>& packet) {
    access::G5LinkLayer link_layer;
    access::IEEE802Dot11PHeader& mac_header = link_layer.ieee802dot11p_header;
    std::copy(request.destination.octets.begin(), request.destination.octets.end(), mac_header.destination);
    std::copy(request.source.octets.begin(), request.source.octets.end(), mac_header.source);
    switch (request.dcc_profile) {
        case dcc::Profile::DP0:
            mac_header.qos_control.priority(access::Priority::AC_VO); // AC_VO (Voice)
            break;
        case dcc::Profile::DP1:
            mac_header.qos_control.priority(access::Priority::AC_VI); // AC_VI (Video)
            break;
        case dcc::Profile::DP2:
            mac_header.qos_control.priority(access::Priority::AC_BE); // AC_BE (Best effort)
            break;
        case dcc::Profile::DP3:
            mac_header.qos_control.priority(access::Priority::AC_BK); // AC_BK (Background)
            break;
        default:
            mac_header.qos_control.priority(access::Priority::AC_BE);
            break;
    }
    auto link_layer_ptr = reinterpret_cast<uint8_t*>(&link_layer);
    packet->layer(OsiLayer::Link) = std::move(ByteBuffer(link_layer_ptr, link_layer_ptr + sizeof(access::G5LinkLayer)));

    uint16_t payload_size = packet->size();
    uint16_t total_size = sizeof(tMKxTxPacket) + payload_size;

    tMKxTxPacket phy = {};
    phy.Hdr.Type = MKXIF_TXPACKET;
    phy.Hdr.Len = total_size;
    phy.TxPacketData.TxAntenna = MKX_ANT_DEFAULT;
    phy.TxPacketData.TxFrameLength = payload_size;
    auto phy_ptr = reinterpret_cast<uint8_t*>(&phy);
    packet->layer(OsiLayer::Physical) = std::move(ByteBuffer(phy_ptr, phy_ptr + sizeof(tMKxTxPacket)));
}

boost::optional<EthernetHeader> strip_cohda_rx_header(CohesivePacket& packet) {
    if (packet.size(OsiLayer::Physical) < sizeof(tMKxRxPacket) + sizeof(access::G5LinkLayer) + access::ieee802dot11p_fcs_length) {
        return boost::none;
    }
    packet.set_boundary(OsiLayer::Physical, sizeof(tMKxRxPacket));

    tMKxRxPacket* phy = reinterpret_cast<tMKxRxPacket*>(&*packet[OsiLayer::Physical].begin());
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
    packet.trim(OsiLayer::Link, packet.size() - access::ieee802dot11p_fcs_length);
    packet.set_boundary(OsiLayer::Link, sizeof(access::G5LinkLayer));

    access::G5LinkLayer* link_layer_ptr = reinterpret_cast<access::G5LinkLayer*>(&*packet[OsiLayer::Link].begin());
    if (!access::check_fixed_fields(*link_layer_ptr)) {
        return boost::none;
    }

    EthernetHeader eth;
    std::memcpy(eth.destination.octets.begin(), link_layer_ptr->ieee802dot11p_header.destination, MacAddress::length_bytes);
    std::memcpy(eth.source.octets.begin(), link_layer_ptr->ieee802dot11p_header.source, MacAddress::length_bytes);
    eth.type = host_cast<uint16_t>(ntoh(link_layer_ptr->llc_snap_header.protocol_id));

    return eth;
}

} // namespace vanetza
