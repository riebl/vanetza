#ifndef G5_LINK_LAYER_HPP_CESAPUOW
#define G5_LINK_LAYER_HPP_CESAPUOW

#include <array>
#include <cstdint>
#include <vanetza/access/access_category.hpp>
#include <vanetza/common/bit_number.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/common/serialization.hpp>
#include <vanetza/net/mac_address.hpp>

namespace vanetza
{
namespace access
{
namespace ieee802
{
namespace dot11
{

/**
 * \brief QoS Control field in IEEE 802.11 MAC header.
 */
struct QosControl
{
    vanetza::uint16be_t raw { 0 };

    /**
     * Set user priority by access category
     * \param ac map this AccessCategory to user priority
     */
    void user_priority(AccessCategory ac);
};

/**
 * \brief Frame Control field in IEEE 802.11 MAC header
 */
struct FrameControl
{
    vanetza::uint16be_t raw { 0 };

    using Protocol = BitNumber<std::uint16_t, 2>; /**< represents protocol version */
    using Type = BitNumber<std::uint16_t, 2>;
    using SubType = BitNumber<std::uint16_t, 4>;

    Protocol protocol() const { return Protocol(raw.get()); }
    Type type() const { return Type(raw.get() >> 2); }
    SubType sub_type() const { return SubType(raw.get() >> 4); }
    bool to_ds() const { return raw.get() & 0x0100; }
    bool from_ds() const { return raw.get() & 0x0200; }
    bool more_fragments() const { return raw.get() & 0x0400; }
    bool retry() const { return raw.get() & 0x0800; }

    /**
     * Create frame control for QoS data frame without any flags
     * \return FrameControl field for QoS data frame
     **/
    static FrameControl qos_data_frame();
};

/**
 * \brief Sequence Control field in IEEE 802.11 MAC header
 */
struct SequenceControl
{
    vanetza::uint16be_t raw { 0 };

    using SequenceNumber = BitNumber<std::uint16_t, 12>;
    using FragmentNumber = BitNumber<std::uint16_t, 4>;

    SequenceNumber sequence_number() const
    {
        return SequenceNumber(raw.get() >> 4);
    }

    FragmentNumber fragment_number() const
    {
        return FragmentNumber(raw.get());
    }
};

/** MAC address representing the BSSID wildcard (all bits set) */
extern const MacAddress bssid_wildcard;

/**
 * \brief MAC header of QoS data frames
 */
struct QosDataHeader
{
    FrameControl frame_control = FrameControl::qos_data_frame();
    uint16be_t duration_or_id;
    MacAddress destination;
    MacAddress source;
    MacAddress bssid = bssid_wildcard;
    SequenceControl sequence_control;
    QosControl qos_control;

    /** length of serialized QoSDataHeader in bytes */
    static constexpr std::size_t length_bytes = 26;
};

/** length of frame check sequence in bytes */
static constexpr std::size_t fcs_length_bytes = 4;

void serialize(OutputArchive&, const QosDataHeader&);
void deserialize(InputArchive&, QosDataHeader&);

} // namespace dot11

/**
 * \brief Logical Link Control header with SNAP extension
 */
struct LlcSnapHeader
{
    std::uint8_t dsap = 0xAA;
    std::uint8_t ssap = 0xAA;
    std::uint8_t control = 0x03;
    std::array<std::uint8_t, 3> oui = {{ 0x00, 0x00, 0x00 }};
    uint16be_t protocol_id;

    LlcSnapHeader(uint16be_t protocol_id) : protocol_id(protocol_id) {}

    static constexpr std::size_t length_bytes = 8;
};

bool operator==(const LlcSnapHeader&, const LlcSnapHeader&);
bool operator!=(const LlcSnapHeader&, const LlcSnapHeader&);

void serialize(OutputArchive&, const LlcSnapHeader&);
void deserialize(InputArchive&, LlcSnapHeader&);

} // namespace ieee802

/**
 * \brief Link layer header used by ITS-G5 stations
 */
struct G5LinkLayer
{
    ieee802::dot11::QosDataHeader mac_header;
    ieee802::LlcSnapHeader llc_snap_header;

    G5LinkLayer();

    static constexpr std::size_t length_bytes =
        ieee802::dot11::QosDataHeader::length_bytes +
        ieee802::LlcSnapHeader::length_bytes;
};

void serialize(OutputArchive&, const G5LinkLayer&);
void deserialize(InputArchive&, G5LinkLayer&);

/**
 * \brief Check whether some link layer header fields contain their expected values.
 * For most explicitly initialized link layer header fields, their (default) value is expected in received frames.
 *
 * \param link_layer G5LinkLayer to check
 * \return whether all fields are set as expected
 */
bool check_fixed_fields(const G5LinkLayer& link_layer);

} // namespace access
} // namespace vanetza

#endif /* G5_LINK_LAYER_HPP_CESAPUOW */
