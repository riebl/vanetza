#include "chunk_packet.hpp"
#include "cohesive_packet.hpp"
#include <cassert>

namespace vanetza
{

static const ByteBufferConvertible empty_byte_buffer_convertible;

ChunkPacket::ChunkPacket()
{
}

ChunkPacket::ChunkPacket(const ChunkPacket& other)
{
    *this = other;
}

ChunkPacket& ChunkPacket::operator=(const ChunkPacket& other)
{
    m_layers.clear();
    for (auto& layer : other.m_layers) {
        m_layers.insert(layer);
    }
    return *this;
}

ByteBufferConvertible& ChunkPacket::layer(OsiLayer layer)
{
    return m_layers[layer];
}

const ByteBufferConvertible& ChunkPacket::layer(OsiLayer layer) const
{
    auto found = m_layers.find(layer);
    if (found != m_layers.end()) {
        assert(found->first == layer);
        return found->second;
    } else {
        return empty_byte_buffer_convertible;
    }
}

std::size_t ChunkPacket::size() const
{
    std::size_t size = 0;
    for(auto& it : m_layers)
    {
        size += it.second.size();
    }

    return size;
}

std::size_t ChunkPacket::size(OsiLayer from, OsiLayer to) const
{
    assert(from <= to);
    std::size_t size = 0;
    for (auto& layer : m_layers) {
        if (layer.first >= from && layer.first <= to) {
            size += layer.second.size();
        }
    }
    return size;
}

} // namespace vanetza

