#include <vanetza/geonet/gbc_memory.hpp>

namespace vanetza
{
namespace geonet
{

void GbcMemory::capacity(std::size_t num)
{
    m_capacity = num < 1 ? 1 : num;

    // remove excessive identifiers
    auto& by_queue_index = m_identifiers.get<by_queue>();
    while (by_queue_index.size() > m_capacity) {
        by_queue_index.pop_front();
    }
}

std::size_t GbcMemory::size() const
{
    return m_identifiers.size();
}

bool GbcMemory::remember(const PacketIdentifier& id)
{
    auto& by_packet_index = m_identifiers.get<by_packet>();
    auto found_packet = by_packet_index.find(id);
    if (found_packet == by_packet_index.end()) {
        // make space for one identifier
        auto& by_queue_index = m_identifiers.get<by_queue>();
        while (!by_queue_index.empty() && by_queue_index.size() >= m_capacity) {
            by_queue_index.pop_front();
        }

        by_queue_index.push_back(id);
        return false;
    } else {
        // packet is already known, just move it to end of queue
        auto found_queue = m_identifiers.project<by_queue>(found_packet);
        auto& by_queue_index = m_identifiers.get<by_queue>();
        by_queue_index.relocate(by_queue_index.end(), found_queue);
        return true;
    }
}

bool GbcMemory::knows(const PacketIdentifier& id) const
{
    return m_identifiers.get<by_packet>().find(id) != m_identifiers.get<by_packet>().end();
}

} // namespace geonet
} // namespace vanetza
