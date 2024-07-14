#ifndef TSB_HEADER_HPP_RS2USUPV
#define TSB_HEADER_HPP_RS2USUPV

#include <vanetza/geonet/position_vector.hpp>
#include <vanetza/geonet/sequence_number.hpp>

namespace vanetza
{
namespace geonet
{

struct TsbHeader
{
public:
    static constexpr std::size_t length_bytes = 4 + LongPositionVector::length_bytes;

    SequenceNumber sequence_number;
    uint16_t reserved = 0;
    LongPositionVector source_position;
};

void serialize(const TsbHeader&, OutputArchive&);
void deserialize(TsbHeader&, InputArchive&);

} // namespace geonet
} // namespace vanetza

#endif /* TSB_HEADER_HPP_RS2USUPV */
