#ifndef CBF_PACKET_BUFFER_HPP_MU3RK5V1
#define CBF_PACKET_BUFFER_HPP_MU3RK5V1

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/cbf_packet_identifier.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/pending_packet.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional/optional.hpp>
#include <cstddef>
#include <list>
#include <memory>

// forward declarations
namespace vanetza
{
class Runtime;

namespace geonet
{
class Address;
class CbfCounter;
class CbfPacket;
class Lifetime;

/**
 * CbfPacket enables handling of conventional packets in a CBF packet buffer.
 * It contains a GeoBroadcast PDU and the network layer payload.
 */
class CbfPacket
{
public:
    CbfPacket(PendingPacket<GbcPdu>&&, const MacAddress& sender);
    CbfPacket(PendingPacket<GbcPdu, const MacAddress&>&&, const MacAddress& sender);

    CbfPacket(CbfPacket&&) = default;
    CbfPacket& operator=(CbfPacket&&) = default;

    /**
     * Get sender of buffered packet
     * \return sender's link-layer address
     */
    const MacAddress& sender() const;

    /**
     * Get source address of buffered packet
     * \return source address
     */
    const Address& source() const;

    /**
     * Get sequence number of buffered packet
     * \return sequence number
     */
    SequenceNumber sequence_number() const;

    /**
     * Reduce lifetime of buffered packet
     * \param d reduce lifetime by this duration
     * \return remaining lifetime
     */
    Clock::duration reduce_lifetime(Clock::duration d);

    /**
     * Length of packet data in bytes (PDU including payload)
     * \return size of packet on wire
     */
    std::size_t length() const;

    PendingPacket<GbcPdu> packet() && { return std::move(m_packet); }

private:
    PendingPacket<GbcPdu> m_packet;
    MacAddress m_sender;
};


/**
 * CbfPacketBuffer facilitates implementation of contention based forwarding
 */
class CbfPacketBuffer
{
public:
    using TimerCallback = std::function<void(PendingPacket<GbcPdu>&&)>;
    using Identifier = CbfPacketIdentifier;

    /**
     * Create CBF packet buffer with bounded capacity
     * \param rt Runtime instance used for internal timers
     * \param cb Callback invoked for each packet on expiry
     * \param cnt CBF counter implementation
     * \param bytes Buffer can hold at most this number of bytes
     */
    CbfPacketBuffer(Runtime& rt, TimerCallback cb, std::unique_ptr<CbfCounter> cnt, std::size_t bytes);
    ~CbfPacketBuffer();

    /**
     * Enqueue a packet and start an associated timer expiring after timeout
     * \param packet Buffer this packet
     * \param timeout CBF timer expiration for this packet
     */
    void add(CbfPacket&& packet, Clock::duration timeout);

    /**
     * Try to remove a packet from buffer.
     * \param id packet identification
     * \return true if packet existed before removal
     */
    bool remove(const Identifier& id);

    /**
     * Update associated packet timer
     * \param id packet identification
     * \param timeout CBF timer expiration
     */
    void update(const Identifier& id, Clock::duration timeout);

    /**
     * Fetch a packet from buffer.
     *
     * Associated timer is automatically stopped and packet removed from buffer.
     * Packet lifetime is reduced by queueing time at return.
     *
     * \param id packet identification
     * \return packet if found in buffer
     */
    boost::optional<CbfPacket> fetch(const Identifier& id);

    /**
     * Find packet in buffer.
     * \param id packet identification
     * \return read-only pointer to packet, nullptr if not found
     */
    const CbfPacket* find(const Identifier& id) const;

    /**
     * Get counter associated with given packet
     * \note packet counter is incremented at each timer update
     * \param id packet identification
     * \return 0 if packet has never been buffered before
     */
    std::size_t counter(const Identifier& packet) const;

private:

    struct Timer
    {
        Timer(const Runtime&, Clock::duration timeout);
        Timer(const Timer&) = default;
        Timer& operator=(const Timer&) = default;
        bool operator<(const Timer&) const;

        Clock::time_point expiry;
        Clock::time_point start;
    };

    using timer_bimap = boost::bimaps::bimap<
        boost::bimaps::multiset_of<Timer>,
        boost::bimaps::unordered_set_of<Identifier, std::hash<Identifier>>,
        boost::bimaps::with_info<std::list<CbfPacket>::iterator>
    >;

    /**
     * Flush all expired packets
     */
    void flush();

    /**
     * Remove timer from map and reschedule timer event if necessary
     */
    void remove_timer(typename timer_bimap::left_map::iterator);

    /**
     * Schedule next timer event at runtime
     */
    void schedule_timer();

    /**
     * Reduce packet lifetime by queueing time
     * \param timer contains queueing start time
     * \param packet associated packet
     * \return true if packet remains valid, false if end of lifetime is reached
     */
    bool reduce_lifetime(const Timer&, CbfPacket&) const;

    std::list<CbfPacket> m_packets;
    timer_bimap m_timers;
    Runtime& m_runtime;
    std::unique_ptr<CbfCounter> m_counter;
    const std::size_t m_capacity_bytes;
    std::size_t m_stored_bytes;
    TimerCallback m_timer_callback;
};

} // namespace geonet
} // namespace vanetza

#endif /* CBF_PACKET_BUFFER_HPP_MU3RK5V1 */

