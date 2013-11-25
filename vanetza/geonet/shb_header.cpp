#include "shb_header.hpp"
#include "serialization.hpp"

namespace vanetza
{
namespace geonet
{

void serialize(const ShbHeader& hdr, OutputArchive& ar)
{
    serialize(hdr.source_position, ar);
    serialize(host_cast(hdr.reserved), ar);
}

void deserialize(ShbHeader& hdr, InputArchive& ar)
{
    deserialize(hdr.source_position, ar);
    deserialize(hdr.reserved, ar);
}

} // namespace geonet
} // namespace vanetza

