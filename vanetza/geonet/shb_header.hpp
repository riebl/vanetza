#ifndef SHB_HEADER_HPP_MRLDRPNK
#define SHB_HEADER_HPP_MRLDRPNK

#include <vanetza/geonet/dcc_field.hpp>
#include <vanetza/geonet/position_vector.hpp>
#include <cstdint>

namespace vanetza
{
namespace geonet
{

struct ShbHeader
{
    ShbHeader();

    static constexpr std::size_t length_bytes = 4 + LongPositionVector::length_bytes;

    LongPositionVector source_position;
    DccField dcc; /* < this field is "reserved" in 102 636-4-1 */
};

void serialize(const ShbHeader&, OutputArchive&);
void deserialize(ShbHeader&, InputArchive&);

} // namespace geonet
} // namespace vanetza

#endif /* SHB_HEADER_HPP_MRLDRPNK */

