#include "shb_header.hpp"
#include "serialization.hpp"

namespace vanetza
{
namespace geonet
{

constexpr std::size_t ShbHeader::length_bytes;

ShbHeader::ShbHeader() : dcc(0u)
{
}

void serialize(const ShbHeader& hdr, OutputArchive& ar)
{
    serialize(hdr.source_position, ar);
    serialize(hdr.dcc, ar);
}

void deserialize(ShbHeader& hdr, InputArchive& ar)
{
    deserialize(hdr.source_position, ar);
    deserialize(hdr.dcc, ar);
}

} // namespace geonet
} // namespace vanetza

