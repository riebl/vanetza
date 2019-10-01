#include "cohda.hpp"
#include <iostream>
#include <cstring>
#include <llc-api.h>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/address.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/common/byte_order.hpp>

namespace vanetza {
/* See ETSI EN 302 663 V1.2.1 (2013-07), Table B.3 */
enum Priority {
    AC_BK = 1, AC_BE = 3, AC_VI = 5, AC_VO = 6
};

/**
 * QoS Control subfields in these bits have predetermined values during transmission and the same expected values
 * during reception either because of 802.11p and the frame type (QoS data frame) used or because of the set of
 * supported features (Ack Policy: only No Ack is supported, A-MSDU present: no A-MSDU supported).
 */
constexpr uint8_t QOS_FIXED_FIELDS_MASK = 0xE8;
constexpr uint8_t QOS_USER_PRIORITY_MASK = 0x07;

struct QOSControl {
    /**
     * 1 bit A-MSDU present (not an A-MSDU = 0)
     * 2 bits Ack Policy (No Ack = 1)
     * 1 bit EOSP (not used)
     * 1 bit MSB of TID, must be 0
     * 3 bits other three bits of TID, used for user priority (according to traffic class)
     */
    uint8_t qos_flags = 0x20;
    uint8_t txop = 0; // Not used
};

struct IEEE802Dot11PHeader {
    uint8_t frame_control_protocol_version_and_type = 0x88; // Only protocol version 0 and QoS data frames supported
    uint8_t frame_control_flags = 0x00; // Not used
    uint16_t duration_or_id = 0; // Not used
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // Operation outside of a BSS, must be set to wildcard (all bits 1)
    uint16_t sequence_control = 0x0000; // 12 bits for sequence number, 4 bits for fragment number; will be set by Cohda LLC during transmission
    QOSControl qos_control;
};

struct LLCHeader {
    uint8_t dsap = 0xAA;
    uint8_t ssap = 0xAA;
    uint8_t control_field = 0x03;
    uint8_t oui[3] = { 0x00, 0x00, 0x00 };
    uint16_t protocol_id = geonet::ether_type.net();
};

struct LinkLayer {
    IEEE802Dot11PHeader ieee802dot11p_header;
    LLCHeader llc_header;
};

constexpr uint8_t IEEE802DOT11P_FCS_LENGTH = 4;

void insert_cohda_tx_header(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket>& packet) {
    LinkLayer link_layer;
    IEEE802Dot11PHeader& mac_header = link_layer.ieee802dot11p_header;
    std::copy(request.destination.octets.begin(), request.destination.octets.end(), mac_header.destination);
    std::copy(request.source.octets.begin(), request.source.octets.end(), mac_header.source);
    switch (request.dcc_profile) {
        case dcc::Profile::DP0:
            mac_header.qos_control.qos_flags |= QOS_USER_PRIORITY_MASK & Priority::AC_VO; // AC_VO (Voice)
            break;
        case dcc::Profile::DP1:
            mac_header.qos_control.qos_flags |= QOS_USER_PRIORITY_MASK & Priority::AC_VI; // AC_VI (Video)
            break;
        case dcc::Profile::DP2:
            mac_header.qos_control.qos_flags |= QOS_USER_PRIORITY_MASK & Priority::AC_BE; // AC_BE (Best effort)
            break;
        case dcc::Profile::DP3:
            mac_header.qos_control.qos_flags |= QOS_USER_PRIORITY_MASK & Priority::AC_BK; // AC_BK (Background)
            break;
        default:
            mac_header.qos_control.qos_flags |= QOS_USER_PRIORITY_MASK & Priority::AC_BE;
            break;
    }
    auto link_layer_ptr = reinterpret_cast<uint8_t*>(&link_layer);
    packet->layer(OsiLayer::Link) = std::move(ByteBuffer(link_layer_ptr, link_layer_ptr + sizeof(LinkLayer)));

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
    if (packet.size(OsiLayer::Physical) < sizeof(tMKxRxPacket) + sizeof(LinkLayer) + IEEE802DOT11P_FCS_LENGTH) {
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
    packet.trim(OsiLayer::Link, packet.size() - IEEE802DOT11P_FCS_LENGTH);
    packet.set_boundary(OsiLayer::Link, sizeof(LinkLayer));

    LinkLayer* link_layer_ptr = reinterpret_cast<LinkLayer*>(&*packet[OsiLayer::Link].begin());
    IEEE802Dot11PHeader& mac_header = link_layer_ptr->ieee802dot11p_header;
    LLCHeader& llc_header = link_layer_ptr->llc_header;
    // For most explicitly initialized link layer header fields, their (default) value is expected in received frames
    LinkLayer expected_link_layer;
    IEEE802Dot11PHeader& expected_mac_header = expected_link_layer.ieee802dot11p_header;
    LLCHeader& expected_llc_header = expected_link_layer.llc_header;

    if (mac_header.frame_control_protocol_version_and_type != expected_mac_header.frame_control_protocol_version_and_type
            || mac_header.frame_control_flags != expected_mac_header.frame_control_flags
            || std::memcmp(mac_header.bssid, expected_mac_header.bssid, sizeof(mac_header.bssid))
            || (mac_header.qos_control.qos_flags & QOS_FIXED_FIELDS_MASK) != (expected_mac_header.qos_control.qos_flags & QOS_FIXED_FIELDS_MASK)
            || std::memcmp(&llc_header, &expected_llc_header, sizeof(llc_header))) {
        return boost::none;
    }

    EthernetHeader eth;
    std::memcpy(eth.destination.octets.begin(), link_layer_ptr->ieee802dot11p_header.destination, MacAddress::length_bytes);
    std::memcpy(eth.source.octets.begin(), link_layer_ptr->ieee802dot11p_header.source, MacAddress::length_bytes);
    eth.type = host_cast<uint16_t>(ntoh(link_layer_ptr->llc_header.protocol_id));

    return eth;
}

} // namespace vanetza
