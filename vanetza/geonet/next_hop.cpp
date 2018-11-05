#include "next_hop.hpp"

namespace vanetza
{
namespace geonet
{

NextHop::NextHop() : m_state(State::Discarded)
{
}

bool NextHop::discarded() const
{
    return m_state == State::Discarded;
}

bool NextHop::buffered() const
{
    return m_state == State::Buffered;
}

bool NextHop::valid() const
{
    return m_state == State::Valid;
}

const MacAddress& NextHop::mac() const
{
    return m_destination;
}

bool NextHop::process() &&
{
    if (valid()) {
        PendingPacket<GbcPdu>(std::move(m_packet), m_destination).process();
        m_state = State::Discarded;
        return true;
    } else {
        return false;
    }
}

void NextHop::transmit(Packet&& packet, const MacAddress& destination)
{
    m_state = NextHop::State::Valid;
    m_packet = std::move(packet);
    m_destination = destination;
}

void NextHop::discard()
{
    m_state = NextHop::State::Discarded;
}

void NextHop::buffer()
{
    m_state = NextHop::State::Buffered;
}

} // namespace geonet
} // namespace vanetza

