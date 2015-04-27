#ifndef PACKET_HPP_LILZ0UWN
#define PACKET_HPP_LILZ0UWN

#include <vanetza/common/byte_view.hpp>
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

/**
 * Create a view of a packet's bytes assigned to a certain layer
 * \param packet
 * \param layer
 * \return a byte view, possibly empty
 */
byte_view_range create_byte_view(const PacketVariant&, OsiLayer);
byte_view_range create_byte_view(const ChunkPacket&, OsiLayer);
byte_view_range create_byte_view(const CohesivePacket&, OsiLayer);

} // namespace geonet
} // namespace vanetza

#endif /* PACKET_HPP_LILZ0UWN */

