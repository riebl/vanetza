#ifndef CBF_PACKET_BUFFER_HPP_MU3RK5V1
#define CBF_PACKET_BUFFER_HPP_MU3RK5V1

#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/sequence_number.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/geonet/traffic_class.hpp>
#include <boost/optional.hpp>
#include <cstddef>
#include <list>
#include <memory>
#include <tuple>


namespace vanetza
{

class MacAddress;

namespace geonet
{

struct CbfPacketData
{
    using PduPtr = std::unique_ptr<GbcPdu>;
    using PayloadPtr = std::unique_ptr<DownPacket>;

    CbfPacketData(PduPtr pdu_, PayloadPtr payload_) :
        pdu(std::move(pdu_)), payload(std::move(payload_)) {}

    PduPtr pdu;
    PayloadPtr payload;
};

class CbfPacketMetaData
{
public:
    CbfPacketMetaData(const MacAddress& sender, Timestamp now);

    /**
     * Set timeout of buffered packet
     * \param timeout duration until timer reaches zero
     * \param now current timestamp
     */
    void set_timeout(units::Duration timeout, Timestamp now);

    /**
     * Get timer expiry
     * \return Timestamp when timer expires
     */
    Timestamp timer_expiry() const { return m_timer_expiry; }

    /**
     * Get timestamp since packet is buffered
     * \return Timestamp since buffering
     */
    Timestamp buffered_since() const { return m_buffered_since; }

    /**
     * Get counter value, initially 1
     * \return counter value
     */
    unsigned counter() const { return m_counter; }

    /**
     * Increment counter value by one
     */
    void increment() { ++m_counter; }

    /**
     * Get sender address of buffered packet
     * \return MAC address of sender
     */
    const MacAddress& sender() const { return m_sender; }

private:
    const MacAddress m_sender;
    unsigned m_counter;
    const Timestamp m_buffered_since;
    Timestamp m_timer_expiry;
};

/**
 * Get length of CBF packet in bytes, i.e. payload plus PDU
 * \param packet CBF packet
 * \return size of CBF packet on wire
 */
std::size_t length(const CbfPacketData&);

class CbfPacketBuffer
{
public:
    typedef CbfPacketData packet_type;
    typedef std::list<packet_type> packet_list;

    /**
     * Create CBF packet buffer with bounded capacity
     * \param bytes Buffer can hold at most this number of bytes
     */
    CbfPacketBuffer(std::size_t bytes);

    ~CbfPacketBuffer();

    /**
     * If a packet is already buffered, drop it.
     * Packets are identified by source MAC address and GeoNet sequence number
     * \param mac MAC address
     * \param sn sequence number
     * \return true if packet was dropped
     */
    bool try_drop(const MacAddress& mac, SequenceNumber sn);

    /**
     * Enqueue a packet and start an associated timer expiring after timeout
     * \param packet Buffer this packet
     * \param sender MAC address of sender (source or forwarder)
     * \param timeout CBF timer expiration for this packet
     * \param now Timestamp of current time
     */
    void push(packet_type&& packet, const MacAddress& sender, units::Duration timeout, Timestamp now);

    /**
     * Get timestamp at which next timer is going to expire.
     * \return next timeout timestamp or empty if there are no timers running
     */
    boost::optional<Timestamp> next_timer_expiry() const;

    /**
     * Get list of packets with expired timer, i.e. packets which need to be sent.
     * \param now Timestamp indicating current time
     * \return list of packets, might be empty
     */
    packet_list packets_to_send(Timestamp now);

    /**
     * Find packet metadata matching MAC address and sequence number
     * \param mac MAC address
     * \param sn sequence number
     * \return meta data if found, empty otherwise
     */
    boost::optional<CbfPacketMetaData&> find(const MacAddress& mac, SequenceNumber sn);
    boost::optional<const CbfPacketMetaData&> find(const MacAddress& mac, SequenceNumber sn) const;

private:
    typedef std::tuple<CbfPacketData, CbfPacketMetaData> node_type;
    std::list<node_type> m_nodes;
    const std::size_t m_capacity;
    std::size_t m_stored;

};

} // namespace geonet
} // namespace vanetza

#endif /* CBF_PACKET_BUFFER_HPP_MU3RK5V1 */

