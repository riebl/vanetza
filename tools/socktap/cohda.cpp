#include "cohda.hpp"
#include <boost/crc.hpp>
#include <iostream>
#include <llc-api.h>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/address.hpp>
#include <vanetza/dcc/profile.hpp>
#include <vanetza/common/byte_order.hpp>

namespace vanetza {

struct LLCHeader {
    uint8_t DSAP = 0xAA;
    uint8_t SSAP = 0xAA;
    uint8_t ControlField = 0x03;
    uint8_t OUI[3] = { 0x00, 0x00, 0x00 };
    uint16_t ProtocolID = geonet::ether_type.net();
};

/* See ETSI EN 302 663 V1.2.1 (2013-07), Table B.3 */
enum tPriority {
    AC_BK = 1, AC_BE = 3, AC_VI = 5, AC_VO = 6
};
constexpr uint8_t QOS_PRIO_MASK = 0x07;

/**
 * 1 bit payload type (MSDU = 0)
 * 2 bits ack policy (No_Ack = 1)
 * 1 bit EOSP (service period = 0)
 * 1 bit unused
 * 3 bits prioriy (set dynamically according to traffic class)
 * 8 bits TXOP (shall be set to 0 when communicating outside of a BSS)
 */
struct tQOSControl {
    uint8_t QOSFlags = 0x20;
    uint8_t TXOP = 0; // not used
};

struct tIEEE80211PHeader {
    uint8_t FrameControlVersionAndType = 0x88;
    uint8_t FrameControlFlags = 0x00; // not used
    uint16_t DurationID = 0x00; // not used
    uint8_t Destination[6];
    uint8_t Source[6];
    uint8_t BSSID[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // Operation outside of a BSS, (see ETSI EN 302 663 V1.2.1 Annex A)
    uint16_t SequenceControl = 0x00; // 12 bits for sequence number, 4 bits for fragment number; will be set by Cohda LLC
    tQOSControl QOSControl;
};

struct LinkLayer {
    tIEEE80211PHeader ieee802dot11p_header;
    LLCHeader llc_header;
};

constexpr uint8_t IEEE80211P_FCS_LENGTH = 4;
constexpr uint32_t CRC32_MAGIC_NUMBER = 0x2144df1c;

void insert_cohda_tx_header(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket>& packet) {
    LinkLayer link_layer;
    std::copy(request.destination.octets.begin(), request.destination.octets.end(), link_layer.ieee802dot11p_header.Destination);
    std::copy(request.source.octets.begin(), request.source.octets.end(), link_layer.ieee802dot11p_header.Source);
    switch (request.dcc_profile) {
        case dcc::Profile::DP0:
            link_layer.ieee802dot11p_header.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_VO; // AC_VO (Voice)
            break;
        case dcc::Profile::DP1:
            link_layer.ieee802dot11p_header.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_VI; // AC_VI (Video)
            break;
        case dcc::Profile::DP2:
            link_layer.ieee802dot11p_header.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BE; // AC_BE (Best effort)
            break;
        case dcc::Profile::DP3:
            link_layer.ieee802dot11p_header.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BK; // AC_BK (Background)
            break;
        default:
            link_layer.ieee802dot11p_header.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BE;
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
    if (packet.size(OsiLayer::Physical) < sizeof(tMKxRxPacket)) {
        return boost::none;
    }
    packet.set_boundary(OsiLayer::Physical, sizeof(tMKxRxPacket));

    tMKxRxPacket* phy = reinterpret_cast<tMKxRxPacket*>(&*packet[OsiLayer::Physical].begin());
    if (phy->Hdr.Type != MKXIF_RXPACKET) {
        return boost::none;
    }
    if (packet.size() != phy->Hdr.Len) {
        return boost::none;
    }
    if (packet.size() - sizeof(tMKxRxPacket) != phy->RxPacketData.RxFrameLength) {
        return boost::none;
    }

    boost::crc_32_type crc_result;
    /*
     * Process the whole 802.11p frame (including its FCS). If the FCS is correct, the CRC result has the same value
     * as the CRC of one block (4 byte) of zeroes.
     */
    crc_result.process_bytes(packet.buffer().data() + sizeof(tMKxRxPacket), packet.size() - sizeof(tMKxRxPacket));
    if (crc_result.checksum() != CRC32_MAGIC_NUMBER) {
        return boost::none;
    }
    packet.trim(OsiLayer::Link, packet.size() - IEEE80211P_FCS_LENGTH);

    if (packet.size(OsiLayer::Link) < sizeof(LinkLayer)) {
        return boost::none;
    }
    packet.set_boundary(OsiLayer::Link, sizeof(LinkLayer));

    LinkLayer* link_layer = reinterpret_cast<LinkLayer*>(&*packet[OsiLayer::Link].begin());

    EthernetHeader eth;
    std::memcpy(eth.destination.octets.begin(), link_layer->ieee802dot11p_header.Destination, MacAddress::length_bytes);
    std::memcpy(eth.source.octets.begin(), link_layer->ieee802dot11p_header.Source, MacAddress::length_bytes);
    eth.type = host_cast<uint16_t>(ntoh(link_layer->llc_header.ProtocolID));

    if (eth.type != geonet::ether_type) {
        return boost::none;
    }
    return eth;
}

} // namespace vanetza
