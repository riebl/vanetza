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

struct tTXPhysical {
    tMKxTxPacket TxMessage;
    tIEEE80211PHeader IEEE80211PHeader;
};

constexpr uint8_t IEEE80211P_FCS_LENGTH = 4;
constexpr uint32_t CRC32_MAGIC_NUMBER = 0x2144df1c;

struct tRXPhysical {
    tMKxRxPacket RxMessage;
    tIEEE80211PHeader IEEE80211PHeader;
};

void insert_cohda_tx_header(const dcc::DataRequest& request, std::unique_ptr<ChunkPacket>& packet) {
    LLCHeader llcData;
    auto llcPtr = reinterpret_cast<uint8_t*>(&llcData);
    packet->layer(OsiLayer::Link) = std::move(ByteBuffer(llcPtr, llcPtr + sizeof(LLCHeader)));

    tTXPhysical phyData;
    phyData.TxMessage = {};
    std::copy(request.destination.octets.begin(), request.destination.octets.end(), phyData.IEEE80211PHeader.Destination);
    std::copy(request.source.octets.begin(), request.source.octets.end(), phyData.IEEE80211PHeader.Source);
    switch (request.dcc_profile) {
        case dcc::Profile::DP0:
            phyData.IEEE80211PHeader.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_VO; // AC_VO (Voice)
            break;
        case dcc::Profile::DP1:
            phyData.IEEE80211PHeader.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_VI; // AC_VI (Video)
            break;
        case dcc::Profile::DP2:
            phyData.IEEE80211PHeader.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BE; // AC_BE (Best effort)
            break;
        case dcc::Profile::DP3:
            phyData.IEEE80211PHeader.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BK; // AC_BK (Background)
            break;
        default:
            phyData.IEEE80211PHeader.QOSControl.QOSFlags |= QOS_PRIO_MASK & tPriority::AC_BE;
            break;
    }

    uint16_t payload_size = sizeof(tIEEE80211PHeader) + packet->size(OsiLayer::Link, OsiLayer::Application);
    uint16_t total_size = sizeof(tMKxTxPacket) + payload_size;

    phyData.TxMessage.Hdr.Type = MKXIF_TXPACKET;
    phyData.TxMessage.Hdr.Len = total_size;

    phyData.TxMessage.TxPacketData.TxAntenna = MKX_ANT_DEFAULT;
    phyData.TxMessage.TxPacketData.TxFrameLength = payload_size;

    auto phyPtr = reinterpret_cast<uint8_t*>(&phyData);
    packet->layer(OsiLayer::Physical) = std::move(ByteBuffer(phyPtr, phyPtr + sizeof(tTXPhysical)));
}

boost::optional<EthernetHeader> strip_cohda_rx_header(CohesivePacket& packet) {
    if (packet.size(OsiLayer::Physical) < sizeof(tRXPhysical) + IEEE80211P_FCS_LENGTH) {
        return boost::none;
    }
    packet.set_boundary(OsiLayer::Physical, sizeof(tRXPhysical));

    tRXPhysical* rxPhy = reinterpret_cast<tRXPhysical*>(&*packet[OsiLayer::Physical].begin());
    if (rxPhy->RxMessage.Hdr.Type != MKXIF_RXPACKET) {
        return boost::none;
    }
    if (packet.size() != rxPhy->RxMessage.Hdr.Len) {
        return boost::none;
    }
    if (packet.size() - sizeof(tMKxRxPacket) != rxPhy->RxMessage.RxPacketData.RxFrameLength) {
        return boost::none;
    }

    boost::crc_32_type crc_result;
    /*
     * Process the whole 802.11p frame (including its FCS). If the FCS is correct, the CRC result has the same value
     * as the CRC of one block (32 bit) of zeroes.
     */
    crc_result.process_bytes(packet.buffer().data() + sizeof(tMKxRxPacket), packet.size() - sizeof(tMKxRxPacket));
    if (crc_result.checksum() != CRC32_MAGIC_NUMBER) {
        return boost::none;
    }
    packet.trim(OsiLayer::Link, packet.size() - IEEE80211P_FCS_LENGTH);

    if (packet.size(OsiLayer::Link) < sizeof(LLCHeader)) {
        return boost::none;
    }
    packet.set_boundary(OsiLayer::Link, sizeof(LLCHeader));

    LLCHeader *llcData = reinterpret_cast<LLCHeader*>(&*packet[OsiLayer::Link].begin());

    EthernetHeader eth;
    std::memcpy(eth.destination.octets.begin(), rxPhy->IEEE80211PHeader.Destination, MacAddress::length_bytes);
    std::memcpy(eth.source.octets.begin(), rxPhy->IEEE80211PHeader.Source, MacAddress::length_bytes);
    eth.type = host_cast<uint16_t>(ntoh(llcData->ProtocolID));

    if (eth.type != geonet::ether_type) {
        return boost::none;
    }
    return eth;
}

} // namespace vanetza
