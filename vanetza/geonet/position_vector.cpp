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

bool operator==(const LongPositionVector& lhs, const LongPositionVector& rhs)
{
    return lhs.gn_addr == rhs.gn_addr
        && lhs.timestamp == rhs.timestamp
        && lhs.latitude == rhs.latitude
        && lhs.longitude == rhs.longitude
        && lhs.speed == rhs.speed
        && lhs.heading == rhs.heading
        && lhs.position_accuracy_indicator == rhs.position_accuracy_indicator;
}

bool operator!=(const LongPositionVector& lhs, const LongPositionVector& rhs)
{
    return !(lhs == rhs);
}

} // namespace geonet
} // namespace vanetza
