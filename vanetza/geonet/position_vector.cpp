#include "areas.hpp"
#include "position_vector.hpp"

namespace vanetza
{
namespace geonet
{

GeodeticPosition LongPositionVector::position() const
{
    return GeodeticPosition {
        static_cast<units::GeoAngle>(latitude),
        static_cast<units::GeoAngle>(longitude)
    };
}

ShortPositionVector::ShortPositionVector(const LongPositionVector& lpv) :
    gn_addr(lpv.gn_addr), timestamp(lpv.timestamp),
    latitude(lpv.latitude), longitude(lpv.longitude)
{
}

} // namespace geonet
} // namespace vanetza
