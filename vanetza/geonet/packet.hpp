#ifndef PACKET_HPP_LILZ0UWN
#define PACKET_HPP_LILZ0UWN

#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace geonet
{

typedef boost::variant<ChunkPacket, CohesivePacket> PacketVariant;
typedef ChunkPacket DownPacket;
typedef PacketVariant UpPacket;

inline std::size_t
size(const CohesivePacket& packet, OsiLayer from, OsiLayer to)
{
    return packet.size(from, to);
}

inline std::size_t
size(const CohesivePacket& packet, OsiLayer layer)
{
    return packet.size(layer);
}

inline std::size_t
size(const ChunkPacket& packet, OsiLayer from, OsiLayer to)
{
    return packet.size(from, to);
}

inline std::size_t
size(const ChunkPacket& packet, OsiLayer layer)
{
    return packet[layer].size();
}

std::size_t size(const PacketVariant&, OsiLayer from, OsiLayer to);
std::size_t size(const PacketVariant&, OsiLayer);
std::unique_ptr<ChunkPacket> duplicate(const PacketVariant&);

} // namespace geonet
} // namespace vanetza

#endif /* PACKET_HPP_LILZ0UWN */

