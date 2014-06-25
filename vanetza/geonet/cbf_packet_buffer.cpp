#include "cbf_packet_buffer.hpp"
#include "pdu.hpp"
#include "packet.hpp"
#include <vanetza/net/mac_address.hpp>
#include <algorithm>
#include <cassert>

namespace vanetza
{
namespace geonet
{

std::size_t length(const CbfPacket& packet)
{
    return (packet.pdu ? packet.pdu->length() : 0) +
        (packet.payload ? packet.payload->size(OsiLayer::Transport, max_osi_layer()) : 0);
}

CbfPacketBuffer::CbfPacketBuffer(std::size_t bytes) :
    m_capacity(bytes), m_stored(0)
{
}

CbfPacketBuffer::~CbfPacketBuffer()
{
}

bool CbfPacketBuffer::try_drop(const MacAddress& mac, SequenceNumber sn)
{
    bool packet_dropped = false;

    auto found = find(mac, sn);
    if (found) {
        m_stored -= length(found.get()->packet);
        m_nodes.erase(found.get());
        packet_dropped = true;
    }

    return packet_dropped;
}

void CbfPacketBuffer::push(CbfPacket&& packet, units::Duration timeout, Timestamp now)
{
    assert(packet.pdu);
    assert(timeout > 0.0 * units::si::seconds);

    const std::size_t packet_size = length(packet);

    // do head drop if necessary
    while (packet_size > m_capacity - m_stored && !m_nodes.empty()) {
        m_stored -= length(m_nodes.front().packet);
        m_nodes.pop_front();
    }

    if (packet_size <= m_capacity) {
        assert(m_capacity - m_stored >= packet_size);
        m_stored += packet_size;
        m_nodes.emplace_back(std::move(packet), timeout, now);
        assert(m_nodes.back().packet.pdu);
    }
}

boost::optional<Timestamp> CbfPacketBuffer::next_timer_expiry() const
{
    boost::optional<Timestamp> next_timer;

    for (const Node& node : m_nodes) {
        if (!next_timer) {
            next_timer = node.timer_expiry;
        } else {
            next_timer = std::min(next_timer.get(), node.timer_expiry);
        }
    }

    return next_timer;
}

CbfPacketBuffer::packet_list CbfPacketBuffer::packets_to_send(Timestamp now)
{
    packet_list packets;
    std::list<decltype(m_nodes)::iterator> deletions;

    // move all packets with expired timeout
    for (auto it = m_nodes.begin(), end = m_nodes.end(); it != end; ++it) {
        packet_type& packet = it->packet;
        assert(packet.pdu);
        if (!now.before(it->timer_expiry)) {
            units::Duration lifetime = packet.pdu->basic().lifetime.decode();
            units::Duration queuetime { now - it->buffered_since };
            m_stored -= length(packet);
            if (queuetime < lifetime) {
                packet.pdu->basic().lifetime.encode(lifetime - queuetime);
                packets.push_back(std::move(packet));
            }
            deletions.push_back(it);
        }
    }

    // delete nodes of moved and dropped packets
    for (auto it : deletions) {
        m_nodes.erase(it);
    }

    return packets;
}

CbfPacketBuffer::Node::Node(packet_type&& p, units::Duration timeout, Timestamp now) :
boost::optional<std::list<CbfPacketBuffer::Node>::iterator>
CbfPacketBuffer::find(const MacAddress& mac, SequenceNumber sn)
{
    boost::optional<std::list<Node>::iterator> result;
    auto found = std::find_if(m_nodes.begin(), m_nodes.end(),
            [&](const Node& node) {
                assert(node.packet.pdu);
                const GeoBroadcastHeader& gbc = node.packet.pdu->extended();
                return (gbc.source_position.gn_addr.mid() == mac && gbc.sequence_number == sn);
            });
    if (found != m_nodes.end()) {
        result = found;
    }
    return result;
}

    packet(std::move(p)),
    buffered_since(now),
    timer_expiry(now + Timestamp::duration_type(timeout))
{
}

} // namespace geonet
} // namespace vanetza

