#ifndef CBF_PACKET_BUFFER_HPP_MU3RK5V1
#define CBF_PACKET_BUFFER_HPP_MU3RK5V1

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/pending_packet.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/sequence_number.hpp>
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/optional/optional.hpp>
#include <cstddef>
#include <list>
#include <memory>
#include <tuple>

// forward declarations
namespace vanetza
{
class Runtime;

namespace geonet
{
class Address;
class CbfPacket;
class Lifetime;

using CbfPacketIdentifier = std::tuple<Address, SequenceNumber>;
CbfPacketIdentifier identifier(const CbfPacket&);
CbfPacketIdentifier identifier(const Address&, SequenceNumber);

} // namespace geonet
} // namespace vanetza


namespace std
{
/// std::hash specialization for CbfPacketIdentifier
template<> struct hash<vanetza::geonet::CbfPacketIdentifier>
{
    size_t operator()(const vanetza::geonet::CbfPacketIdentifier&) const;
};
} // namespace std


namespace vanetza
{
namespace geonet
{

/**
 * CbfPacket enables handling of conventional packets in a CBF packet buffer.
 * It contains a GeoBroadcast PDU, Payload and an additional counter.
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
     * Get counter of buffered packet
     * \return reference to counter (initially 1)
     */
    unsigned& counter() { return m_counter; }

    /**
     * Get counter of buffered packet
     * \return copy of counter
     */
    unsigned counter() const { return m_counter; }

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
    const MacAddress m_sender;
    unsigned m_counter;
};


/**
 * CbfPacketBuffer facilitates implementation of contention based forwarding
 */
class CbfPacketBuffer
{
public:
    using TimerCallback = std::function<void(PendingPacket<GbcPdu>&&)>;

    /**
     * Create CBF packet buffer with bounded capacity
     * \param rt Runtime instance used for internal timers
     * \param timer_cb Callback invoked for each packet on expiry
     * \param bytes Buffer can hold at most this number of bytes
     */
    CbfPacketBuffer(Runtime& rt, TimerCallback timer_cb, std::size_t bytes);
    ~CbfPacketBuffer();

    /**
     * Try to drop a packet from buffer identified by source address and sequence number.
     * \param src source address
     * \param sn sequence number
     * \return true if packet was dropped
     */
    bool try_drop(const Address& source, SequenceNumber sn);

    /**
     * Enqueue a packet and start an associated timer expiring after timeout
     * \param packet Buffer this packet
     * \param timeout CBF timer expiration for this packet
     */
    void enqueue(CbfPacket&& packet, Clock::duration timeout);

    /**
     * Fetch a packet from buffer.
     *
     * Associated timer is automatically stopped and packet removed from buffer.
     * Enqueue packet again if it shall not be dropped.
     * Packet lifetime is reduced by queueing time at return.
     *
     * \param source source address
     * \param sn sequence number
     * \return packet matching source address and sequence number
     */
    boost::optional<CbfPacket> fetch(const Address& source, SequenceNumber sn);

    /**
     * Find packet in buffer.
     * \param source source address
     * \param sn sequence number
     * \return read-only pointer to packet, nullptr if not found
     */
    const CbfPacket* find(const Address& source, SequenceNumber sn) const;

private:
    using Identifier = CbfPacketIdentifier;

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
    const std::size_t m_capacity_bytes;
    std::size_t m_stored_bytes;
    TimerCallback m_timer_callback;
};

} // namespace geonet
} // namespace vanetza

#endif /* CBF_PACKET_BUFFER_HPP_MU3RK5V1 */

