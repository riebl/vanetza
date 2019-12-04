#include <vanetza/access/g5_link_layer.hpp>
#include <vanetza/access/ethertype.hpp>
#include <cstring>

namespace vanetza
{
namespace access
{

static const ieee802::LlcSnapHeader default_llc_header { ethertype::GeoNetworking };

G5LinkLayer::G5LinkLayer() :
    llc_snap_header(default_llc_header)
{
}

void serialize(OutputArchive& ar, const G5LinkLayer& g5)
{
    serialize(ar, g5.mac_header);
    serialize(ar, g5.llc_snap_header);
}

void deserialize(InputArchive& ar, G5LinkLayer& g5)
{
    deserialize(ar, g5.mac_header);
    deserialize(ar, g5.llc_snap_header);
}

bool check_fixed_fields(const G5LinkLayer& link_layer)
{
    static const auto default_frame_control = ieee802::dot11::FrameControl::qos_data_frame();
    static const ieee802::dot11::QosControl default_qos_control;

    // all frame control flags are fixed for now
    static const std::uint16_t frame_control_fixed = 0xFFFF;

    // EOSP + A-MSDU + TXOP limit fixed, TID (LSB part = UP) and Ack policy are variable
    static const std::uint16_t qos_control_fixed = 0xFF98;

    const ieee802::dot11::QosDataHeader& mac = link_layer.mac_header;
    const bool frame_control_ok =
        (mac.frame_control.raw.get() & frame_control_fixed) == (default_frame_control.raw.get() & frame_control_fixed);
    const bool qos_control_ok =
        (mac.qos_control.raw.get() & qos_control_fixed) == (default_qos_control.raw.get() & qos_control_fixed);
    return frame_control_ok && qos_control_ok &&
                mac.sequence_control.fragment_number() == 0 &&
                mac.bssid == ieee802::dot11::bssid_wildcard &&
                link_layer.llc_snap_header == default_llc_header;
}

namespace ieee802
{
namespace dot11
{

// Operation outside of a BSS, must be set to wildcard (all bits 1)
const MacAddress bssid_wildcard = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

void QosControl::user_priority(AccessCategory access_category)
{
    std::uint16_t tmp = raw.get();
    tmp &= ~0x000F; // clear all TID bits
    tmp |= static_cast<std::uint16_t>(access_category) & 0x07;
    raw = static_cast<uint16be_t>(tmp);
}

FrameControl FrameControl::qos_data_frame()
{
    FrameControl frame_control;
    frame_control.raw = host_cast<std::uint16_t>(0x8800);
    return frame_control;
}

void serialize(OutputArchive& ar, const QosDataHeader& mac)
{
    serialize(ar, mac.frame_control.raw);
    serialize(ar, mac.duration_or_id);
    serialize(ar, mac.destination);
    serialize(ar, mac.source);
    serialize(ar, mac.bssid);
    serialize(ar, mac.sequence_control.raw);
    serialize(ar, mac.qos_control.raw);
}

void deserialize(InputArchive& ar, QosDataHeader& mac)
{
    deserialize(ar, mac.frame_control.raw);
    deserialize(ar, mac.duration_or_id);
    deserialize(ar, mac.destination);
    deserialize(ar, mac.source);
    deserialize(ar, mac.bssid);
    deserialize(ar, mac.sequence_control.raw);
    deserialize(ar, mac.qos_control.raw);
}

} // namespace dot11

void serialize(OutputArchive& ar, const LlcSnapHeader& snap)
{
    serialize(ar, snap.dsap);
    serialize(ar, snap.ssap);
    serialize(ar, snap.control);
    for (std::uint8_t byte : snap.oui) {
        ar << byte;
    }
    serialize(ar, snap.protocol_id);
}

void deserialize(InputArchive& ar, LlcSnapHeader& snap)
{
    deserialize(ar, snap.dsap);
    deserialize(ar, snap.ssap);
    deserialize(ar, snap.control);
    for (std::uint8_t& byte : snap.oui) {
        ar >> byte;
    }
    deserialize(ar, snap.protocol_id);
}

bool operator==(const LlcSnapHeader& a, const LlcSnapHeader& b)
{
    return a.dsap == b.dsap && a.ssap == b.ssap && a.control == b.control &&
        a.oui == b.oui && a.protocol_id == b.protocol_id;
}

bool operator!=(const LlcSnapHeader& a, const LlcSnapHeader& b)
{
    return !(a == b);
}

} // namespace ieee802

} // namespace access
} // namespace vanetza
