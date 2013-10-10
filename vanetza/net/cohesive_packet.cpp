#include "cohesive_packet.hpp"
#include <cassert>
#include <iterator>

namespace vanetza
{

constexpr unsigned layer_index(OsiLayer layer)
{
    return static_cast<unsigned>(layer);
}

static_assert(layer_index(min_osi_layer()) == 1, "Lowest OSI layer index broken");


CohesivePacket::CohesivePacket(const ByteBuffer& buffer, OsiLayer layer) :
    m_buffer(buffer)
{
    reset_iterators(layer);
}

CohesivePacket::CohesivePacket(ByteBuffer&& buffer, OsiLayer layer) :
    m_buffer(std::move(buffer))
{
    reset_iterators(layer);
}

auto CohesivePacket::operator[](OsiLayer layer) const -> buffer_const_range
{
    return get(layer_index(layer));
}

auto CohesivePacket::operator[](OsiLayer layer) -> buffer_range
{
    return get(layer_index(layer));
}

void CohesivePacket::set_boundary(OsiLayer layer, unsigned bytes)
{
    const unsigned layer_idx = layer_index(layer);
    assert(get(layer_idx).size() >= bytes);
    m_iterators[layer_idx] = m_iterators[layer_idx - 1] + bytes;
}

std::size_t CohesivePacket::size() const
{
    return m_buffer.size();
}

std::size_t CohesivePacket::size(OsiLayer single_layer) const
{
    return get(layer_index(single_layer)).size();
}

std::size_t CohesivePacket::size(OsiLayer from, OsiLayer to) const
{
    auto begin = m_iterators[layer_index(from) - 1];
    auto end = m_iterators[layer_index(to)];
    return std::distance(begin, end);
}

void CohesivePacket::reset_iterators(OsiLayer ins_layer)
{
    unsigned layer_idx = 0;

    const unsigned ins_layer_idx = layer_index(ins_layer);
    for (unsigned i = 0; i < ins_layer_idx; ++i) {
        m_iterators[layer_idx++] = m_buffer.begin();
    }

    const unsigned max_layer_idx = layer_index(max_osi_layer());
    for (unsigned i = ins_layer_idx; i <= max_layer_idx; ++i) {
        m_iterators[layer_idx++] = m_buffer.end();
    }

    assert(m_iterators.size() == layer_idx);
}

auto CohesivePacket::get(unsigned layer_idx) -> buffer_range
{
    assert(layer_idx > 0);
    assert(layer_idx < m_iterators.size());
    return buffer_range(m_iterators[layer_idx - 1], m_iterators[layer_idx]);
}

auto CohesivePacket::get(unsigned layer_idx) const -> buffer_const_range
{
    assert(layer_idx > 0);
    assert(layer_idx < m_iterators.size());
    return buffer_const_range(m_iterators[layer_idx - 1], m_iterators[layer_idx]);
}

} // namespace vanetza

