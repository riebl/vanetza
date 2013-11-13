#include "position_vector.hpp"

namespace vanetza
{
namespace geonet
{

ShortPositionVector::ShortPositionVector(const LongPositionVector& lpv) :
    gn_addr(lpv.gn_addr), timestamp(lpv.timestamp),
    latitude(lpv.latitude), longitude(lpv.longitude)
{
}

} // namespace geonet
} // namespace vanetza
