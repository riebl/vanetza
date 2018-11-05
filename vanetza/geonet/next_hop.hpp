#ifndef NEXT_HOP_HPP_ON0AKMBY
#define NEXT_HOP_HPP_ON0AKMBY

#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/pending_packet.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/net/mac_address.hpp>

namespace vanetza
{
namespace geonet
{

/**
 * NextHop is the result of GeoNet forwarding algorithms.
 * It may convey a destination link-layer address or one of the states "discarded" and "buffered".
 */
class NextHop
{
public:
    using Packet = PendingPacket<GbcPdu, const MacAddress&>;

    NextHop();
    NextHop(NextHop&&) = default;
    NextHop& operator=(NextHop&&) = default;

    /**
     * Test if forwarding decision is to discard the packet.
     * \return true if discarded
     */
    bool discarded() const;

    /**
     * Test if forwarding decided to buffer the packet.
     * \return true if packet got buffered
     */
    bool buffered() const;

    /**
     * Test if stored packet and link-layer address are valid.
     * \return if valid
     */
    bool valid() const;

    /**
     * Access stored link-layer address.
     *
     * The returned address is only meaningful if NextHop is valid.
     * \return link-layer address
     */
    const MacAddress& mac() const;

    /**
     * Prepare for immediate packet transmission (not discarded, not buffered).
     *
     * valid() will return true after invocation of this method.
     * \param packet the packet to be transmitted
     * \param destination link-layer destination address
     */
    void transmit(Packet&& packet, const MacAddress& destination);

    /**
     * Set the NextHop state to discarded.
     */
    void discard();

    /**
     * Set the NextHop state to buffered.
     */
    void buffer();

    /**
     * Invoke further packet processing.
     *
     * It is safe to call this method though packet has been discarded or buffered.
     * \return true if a valid packet (after previous transmit()) has been processed
     */
    bool process() &&;

private:
    enum class State { Valid, Discarded, Buffered };

    State m_state;
    MacAddress m_destination;
    Packet m_packet;
};

} // namespace geonet
} // namespace vanetza

#endif /* NEXT_HOP_HPP_ON0AKMBY */

