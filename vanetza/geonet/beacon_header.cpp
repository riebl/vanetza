#include "beacon_header.hpp"
#include "serialization.hpp"

namespace vanetza
{
namespace geonet
{

void serialize(const BeaconHeader& hdr, OutputArchive& ar)
{
    serialize(hdr.source_position, ar);
}

} // namespace geonet
} // namespace vanetza

