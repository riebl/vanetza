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


namespace vanetza
{

class MacAddress;

namespace geonet
{

struct CbfPacket
{
    using PduPtr = std::unique_ptr<GbcPdu>;
    using PayloadPtr = std::unique_ptr<DownPacket>;

    CbfPacket(PduPtr pdu_) :
        pdu(std::move(pdu_)) {}
    CbfPacket(PduPtr pdu_, PayloadPtr payload_) :
        pdu(std::move(pdu_)), payload(std::move(payload_)) {}

    PduPtr pdu;
    PayloadPtr payload;
};

/**
 * Get length of CBF packet in bytes, i.e. payload plus PDU
 * \param packet CBF packet
 * \return size of CBF packet on wire
 */
std::size_t length(const CbfPacket&);

class CbfPacketBuffer
{
public:
    typedef CbfPacket packet_type;
    typedef std::list<CbfPacket> packet_list;

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
     * Get counter of stored packet
     * \param mac MAC address of packet
     * \param sn sequence number of packet
     * \return 0 if packet is not buffered, counter value otherwise (starting with 1)
     */
    unsigned counter(const MacAddress& mac, SequenceNumber sn) const;

    /**
     * Increment counter of stored packet by one
     * \param mac MAC address of packet
     * \param sn sequence number of packet
     */
    void increment(const MacAddress& mac, SequenceNumber sn);

    /**
     * Get sender of stored packet
     * \param mac MAC address of packet
     * \param sn sequence number of packet
     * \return MAC address of sender or broadcast address if no matching packet is buffered
     */
    const MacAddress& sender(const MacAddress& mac, SequenceNumber sn) const;

private:
    struct Node
    {
        Node(packet_type&&, const MacAddress& sender, units::Duration timeout, Timestamp now);

        packet_type packet;
        const MacAddress sender;
        const Timestamp buffered_since;
        const Timestamp timer_expiry;
        unsigned counter;
    };

    std::list<Node> m_nodes;
    const std::size_t m_capacity;
    std::size_t m_stored;

    boost::optional<std::list<Node>::iterator> find(const MacAddress& mac, SequenceNumber sn);
    boost::optional<std::list<Node>::const_iterator> find(const MacAddress& mac, SequenceNumber sn) const;
};

} // namespace geonet
} // namespace vanetza

#endif /* CBF_PACKET_BUFFER_HPP_MU3RK5V1 */

