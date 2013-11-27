#include "packet.hpp"

namespace vanetza
{

Packet::Packet()
{
}

void Packet::swap(OsiLayer layer, ByteBuffer& replacement)
{
    ByteBuffer& stored = mBuffers[layer];
    stored.swap(replacement);
}

const ByteBuffer& Packet::operator[](OsiLayer layer) const
{
    auto match = mBuffers.find(layer);
    if (match == mBuffers.end()) {
        static const ByteBuffer scEmptyBuffer;
        return scEmptyBuffer;
    } else {
        return match->second;
    }
}

std::size_t Packet::size() const
{
    std::size_t packet_size = 0;
    for (const auto& it : *this) {
        packet_size += it.second.size();
    }
    return packet_size;
}

void Packet::clear()
{
    for (auto& it : mBuffers) {
        it.second.clear();
    }
}

} // namespace vanetza

