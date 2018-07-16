#include "header.hpp"
#include <vanetza/common/serialization.hpp>
#include <vanetza/common/serialization_buffer.hpp>

namespace vanetza
{
namespace btp
{

using vanetza::serialize;
using vanetza::deserialize;

constexpr std::size_t HeaderA::length_bytes;
constexpr std::size_t HeaderB::length_bytes;

void serialize(OutputArchive& ar, const HeaderA& hdr)
{
    serialize(ar, hdr.destination_port);
    serialize(ar, hdr.source_port);
}

void deserialize(InputArchive& ar, HeaderA& hdr)
{
    deserialize(ar, hdr.destination_port);
    deserialize(ar, hdr.source_port);
}

void serialize(OutputArchive& ar, const HeaderB& hdr)
{
    serialize(ar, hdr.destination_port);
    serialize(ar, hdr.destination_port_info);
}

void deserialize(InputArchive& ar, HeaderB& hdr)
{
    deserialize(ar, hdr.destination_port);
    deserialize(ar, hdr.destination_port_info);
}

HeaderA parse_btp_a(CohesivePacket& packet)
{
    HeaderA hdr;
    deserialize_from_range(hdr, packet[OsiLayer::Transport]);
    packet.set_boundary(OsiLayer::Transport, btp::HeaderA::length_bytes);
    return hdr;
}

HeaderA parse_btp_a(ChunkPacket& packet)
{
    HeaderA hdr;
    ByteBuffer tmp;
    packet[OsiLayer::Transport].convert(tmp);
    deserialize_from_buffer(hdr, tmp);
    return hdr;
}

HeaderA parse_btp_a(PacketVariant& packet)
{
    struct parse_btp_visitor : public boost::static_visitor<HeaderA>
    {
        HeaderA operator()(CohesivePacket& packet) {
            return parse_btp_a(packet);
        }

        HeaderA operator()(ChunkPacket& packet) {
            return parse_btp_a(packet);
        }
    };

    parse_btp_visitor visitor;
    return boost::apply_visitor(visitor, packet);
}

HeaderB parse_btp_b(CohesivePacket& packet)
{
    HeaderB hdr;
    deserialize_from_range(hdr, packet[OsiLayer::Transport]);
    packet.set_boundary(OsiLayer::Transport, btp::HeaderB::length_bytes);
    return hdr;
}

HeaderB parse_btp_b(ChunkPacket& packet)
{
    HeaderB hdr;
    ByteBuffer tmp;
    packet[OsiLayer::Transport].convert(tmp);
    deserialize_from_buffer(hdr, tmp);
    return hdr;
}

HeaderB parse_btp_b(PacketVariant& packet)
{
    struct parse_btp_visitor : public boost::static_visitor<HeaderB>
    {
        HeaderB operator()(CohesivePacket& packet) {
            return parse_btp_b(packet);
        }

        HeaderB operator()(ChunkPacket& packet) {
            return parse_btp_b(packet);
        }
    };

    parse_btp_visitor visitor;
    return boost::apply_visitor(visitor, packet);
}

} // namespace btp
} // namespace vanetza
