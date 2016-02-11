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

bool node_match(
        const MacAddress& mac, SequenceNumber sn,
        const std::tuple<CbfPacketData, CbfPacketMetaData>& node)
{
    assert(std::get<0>(node).pdu);
    const GeoBroadcastHeader& gbc = std::get<0>(node).pdu->extended();
    return (gbc.source_position.gn_addr.mid() == mac && gbc.sequence_number == sn);
}

std::size_t length(const CbfPacketData& packet)
{
    return (packet.pdu ? get_length(*packet.pdu) : 0) +
        (packet.payload ? packet.payload->size(OsiLayer::Transport, max_osi_layer()) : 0);
}


CbfPacketMetaData::CbfPacketMetaData(const MacAddress& sender, Timestamp now) :
    m_sender(sender), m_counter(1), m_buffered_since(now), m_timer_expiry(now)
{
}

void CbfPacketMetaData::set_timeout(units::Duration timeout, Timestamp now)
{
    assert(!now.before(m_buffered_since));
    m_timer_expiry = now + Timestamp::duration_type(timeout);
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

    auto found = std::find_if(m_nodes.begin(), m_nodes.end(),
            std::bind(node_match, mac, sn, std::placeholders::_1));
    if (found != m_nodes.end()) {
        m_stored -= length(std::get<0>(*found));
        m_nodes.erase(found);
        packet_dropped = true;
    }

    return packet_dropped;
}

void CbfPacketBuffer::push(CbfPacketData&& packet, const MacAddress& sender,
        units::Duration timeout, Timestamp now)
{
    assert(packet.pdu);
    assert(timeout > 0.0 * units::si::seconds);

    const std::size_t packet_size = length(packet);

    // do head drop if necessary
    while (packet_size > m_capacity - m_stored && !m_nodes.empty()) {
        m_stored -= length(std::get<0>(m_nodes.front()));
        m_nodes.pop_front();
    }

    if (packet_size <= m_capacity) {
        assert(m_capacity - m_stored >= packet_size);
        m_stored += packet_size;
        CbfPacketMetaData meta { sender, now };
        meta.set_timeout(timeout, now);
        m_nodes.emplace_back(std::move(packet), std::move(meta));
        assert(std::get<0>(m_nodes.back()).pdu);
    }
}

boost::optional<Timestamp> CbfPacketBuffer::next_timer_expiry() const
{
    boost::optional<Timestamp> next_timer;

    for (const auto& node : m_nodes) {
        if (!next_timer) {
            next_timer = std::get<1>(node).timer_expiry();
        } else {
            next_timer = std::min(next_timer.get(), std::get<1>(node).timer_expiry());
        }
    }

    return next_timer;
}

CbfPacketBuffer::packet_list CbfPacketBuffer::packets_to_send(Timestamp now)
{
    packet_list packets;

    // move all packets with expired timeout
    for (auto it = m_nodes.begin(); it != m_nodes.end();) {
        packet_type& packet = std::get<0>(*it);
        CbfPacketMetaData& meta = std::get<1>(*it);
        assert(packet.pdu);
        if (!now.before(meta.timer_expiry())) {
            units::Duration lifetime = packet.pdu->basic().lifetime.decode();
            units::Duration queuetime { now - meta.buffered_since() };
            m_stored -= length(packet);
            if (queuetime < lifetime) {
                packet.pdu->basic().lifetime.encode(lifetime - queuetime);
                packets.push_back(std::move(packet));
            }

            it = m_nodes.erase(it);
        } else {
            ++it;
        }
    }

    return packets;
}

boost::optional<CbfPacketMetaData&>
CbfPacketBuffer::find(const MacAddress& mac, SequenceNumber sn)
{
    using std::placeholders::_1;
    boost::optional<CbfPacketMetaData&> result;
    auto found = std::find_if(m_nodes.begin(), m_nodes.end(), std::bind(node_match, mac, sn, _1));
    if (found != m_nodes.end()) {
        result = std::get<1>(*found);
    }
    return result;
}

boost::optional<const CbfPacketMetaData&>
CbfPacketBuffer::find(const MacAddress& mac, SequenceNumber sn) const
{
    using std::placeholders::_1;
    boost::optional<const CbfPacketMetaData&> result;
    auto found = std::find_if(m_nodes.begin(), m_nodes.end(), std::bind(node_match, mac, sn, _1));
    if (found != m_nodes.end()) {
        result = std::get<1>(*found);
    }
    return result;
}

} // namespace geonet
} // namespace vanetza

