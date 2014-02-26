#ifndef PACKET_HPP_LILZ0UWN
#define PACKET_HPP_LILZ0UWN

#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace geonet
{
namespace detail
{

typedef boost::variant<ChunkPacket, CohesivePacket> PacketVariant;

} // namespace detail

typedef ChunkPacket DownPacket;

#ifdef VANETZA_GEONET_USE_PACKET_VARIANT
typedef typename detail::PacketVariant UpPacket;
#else
typedef CohesivePacket UpPacket;
#endif

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

std::size_t size(const detail::PacketVariant&, OsiLayer from, OsiLayer to);
std::size_t size(const detail::PacketVariant&, OsiLayer);

} // namespace geonet
} // namespace vanetza

#endif /* PACKET_HPP_LILZ0UWN */

