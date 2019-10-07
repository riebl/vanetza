#ifndef G5_LINK_LAYER
#define G5_LINK_LAYER
#include <cstdint>
#include <cstring>
#include <vanetza/geonet/router.hpp>

namespace vanetza {
namespace access {
namespace { // anonymous namespace for local constants
/**
 * QoS Control subfields in these bits have predetermined values during transmission and the same expected values
 * during reception either because of 802.11p and the frame type (QoS data frame) used or because of the set of
 * supported features (Ack Policy: only No Ack is supported, A-MSDU present: no A-MSDU supported).
 */
constexpr uint8_t qos_fixed_fields_mask = 0xE8;
constexpr uint8_t qos_user_priority_mask = 0x07;
} // namespace

/* See ETSI EN 302 663 V1.2.1 (2013-07), Table B.3 */
enum Priority {
    AC_BK = 1, AC_BE = 3, AC_VI = 5, AC_VO = 6
};

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

    void priority(Priority prio) { qos_flags |= static_cast<int>(prio) & qos_user_priority_mask; }
};

struct IEEE802Dot11PHeader {
    uint8_t frame_control_protocol_version_and_type = 0x88; // Only protocol version 0 and QoS data frames supported
    uint8_t frame_control_flags = 0x00; // Not supported
    uint16_t duration_or_id = 0; // Not used
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; // Operation outside of a BSS, must be set to wildcard (all bits 1)
    uint16_t sequence_control = 0x0000; // 12 bits for sequence number, 4 bits for fragment number
    QOSControl qos_control;
};

constexpr uint8_t ieee802dot11p_fcs_length = 4;

struct LLCSNAPHeader {
    uint8_t dsap = 0xAA;
    uint8_t ssap = 0xAA;
    uint8_t control_field = 0x03;
    uint8_t oui[3] = { 0x00, 0x00, 0x00 };
    uint16_t protocol_id = geonet::ether_type.net();
};

struct G5LinkLayer {
    IEEE802Dot11PHeader ieee802dot11p_header;
    LLCSNAPHeader llc_snap_header;
};

/**
 * \brief Check whether some link layer header fields contain their expected values.
 * For most explicitly initialized link layer header fields, their (default) value is expected in received frames.
 *
 * \param link_layer G5LinkLayer to check
 * \return whether all expected values are present
 */
bool check_fixed_fields(const G5LinkLayer& link_layer) {
    const IEEE802Dot11PHeader& mac_header = link_layer.ieee802dot11p_header;
    const LLCSNAPHeader& llc_header = link_layer.llc_snap_header;
    G5LinkLayer default_link_layer;
    IEEE802Dot11PHeader& default_mac_header = default_link_layer.ieee802dot11p_header;
    LLCSNAPHeader& default_llc_header = default_link_layer.llc_snap_header;
    return mac_header.frame_control_protocol_version_and_type == default_mac_header.frame_control_protocol_version_and_type
                && mac_header.frame_control_flags == default_mac_header.frame_control_flags
                && !std::memcmp(mac_header.bssid, default_mac_header.bssid, sizeof(mac_header.bssid))
                && (mac_header.qos_control.qos_flags & qos_fixed_fields_mask) == (default_mac_header.qos_control.qos_flags & qos_fixed_fields_mask)
                && !std::memcmp(&llc_header, &default_llc_header, sizeof(llc_header));
}

} // namespace access
} // namespace vanetza

#endif /* G5_LINK_LAYER */
