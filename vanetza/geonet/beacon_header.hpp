#ifndef BEACON_HEADER_HPP_1NRWPHXO
#define BEACON_HEADER_HPP_1NRWPHXO

#include <vanetza/geonet/position_vector.hpp>

namespace vanetza
{
namespace geonet
{

struct BeaconHeader
{
public:
    static const std::size_t length_bytes = LongPositionVector::length_bytes;

    LongPositionVector source_position;
};


} // namespace geonet
} // namespace vanetza

#endif /* BEACON_HEADER_HPP_1NRWPHXO */

