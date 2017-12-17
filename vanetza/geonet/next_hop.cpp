#include "next_hop.hpp"

namespace vanetza
{
namespace geonet
{

NextHop::NextHop() : m_state(State::DISCARDED)
{
}

bool NextHop::discarded() const
{
    return m_state == State::DISCARDED;
}

bool NextHop::buffered() const
{
    return m_state == State::BUFFERED;
}

bool NextHop::valid() const
{
    return m_state == State::VALID;
}

const MacAddress& NextHop::mac() const
{
    return m_destination;
}

bool NextHop::process() &&
{
    if (valid()) {
        PendingPacket<GbcPdu>(std::move(m_packet), m_destination).process();
        m_state = State::DISCARDED;
        return true;
    } else {
        return false;
    }
}

void NextHop::transmit(Packet&& packet, const MacAddress& destination)
{
    m_state = NextHop::State::VALID;
    m_packet = std::move(packet);
    m_destination = destination;
}

void NextHop::discard()
{
    m_state = NextHop::State::DISCARDED;
}

void NextHop::buffer()
{
    m_state = NextHop::State::BUFFERED;
}

} // namespace geonet
} // namespace vanetza

