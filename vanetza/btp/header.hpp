#ifndef HEADER_HPP_FNKGEM7C
#define HEADER_HPP_FNKGEM7C

#include <vanetza/common/byte_order.hpp>
#include <vanetza/common/serialization.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <cstdint>

namespace vanetza
{
namespace btp
{

typedef uint16be_t port_type;

// interactive packet transport
struct HeaderA
{
    static constexpr std::size_t length_bytes = 4;

    port_type destination_port;
    port_type source_port;
};

static_assert(sizeof(HeaderA) == HeaderA::length_bytes, "Wrong size");

void serialize(OutputArchive&, const HeaderA&);
void deserialize(InputArchive&, HeaderA&);
HeaderA parse_btp_a(ChunkPacket&);
HeaderA parse_btp_a(CohesivePacket&);
HeaderA parse_btp_a(PacketVariant&);

// non-interactive packet transport
struct HeaderB
{
    static constexpr std::size_t length_bytes = 4;

    port_type destination_port;
    uint16be_t destination_port_info;
};

static_assert(sizeof(HeaderB) == HeaderB::length_bytes, "Wrong size");

void serialize(OutputArchive&, const HeaderB&);
void deserialize(InputArchive&, HeaderB&);
HeaderB parse_btp_b(ChunkPacket&);
HeaderB parse_btp_b(CohesivePacket&);
HeaderB parse_btp_b(PacketVariant&);

} // namepsace btp
} // namespace vanetza

#endif /* HEADER_HPP_FNKGEM7C */
