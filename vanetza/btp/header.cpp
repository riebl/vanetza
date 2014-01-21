#include "header.hpp"
#include <vanetza/geonet/serialization.hpp>

namespace vanetza
{
namespace btp
{

void serialize(const HeaderB& hdr, geonet::OutputArchive& ar)
{
    geonet::serialize(hdr.destination_port, ar);
    geonet::serialize(hdr.destination_port_info, ar);
}

void deserialize(HeaderB& hdr, geonet::InputArchive& ar)
{
    geonet::deserialize(hdr.destination_port, ar);
    geonet::deserialize(hdr.destination_port_info, ar);
}

} // namespace btp
} // namespace vanetza

