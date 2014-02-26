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

} // namespace geonet
} // namespace vanetza

#endif /* PACKET_HPP_LILZ0UWN */

