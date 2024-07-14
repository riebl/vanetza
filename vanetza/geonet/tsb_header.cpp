#include "tsb_header.hpp"
#include "serialization.hpp"

namespace vanetza
{
namespace geonet
{

constexpr std::size_t TsbHeader::length_bytes;

void serialize(const TsbHeader& hdr, OutputArchive& ar)
{
    serialize(hdr.sequence_number, ar);
    serialize(hdr.reserved, ar);
    serialize(hdr.source_position, ar);
}

void deserialize(TsbHeader& hdr, InputArchive& ar)
{
    deserialize(hdr.sequence_number, ar);
    deserialize(hdr.reserved, ar);
    deserialize(hdr.source_position, ar);
}

} // namespace geonet
} // namespace vanetza