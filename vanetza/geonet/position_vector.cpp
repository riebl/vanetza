#include "areas.hpp"
#include "position_vector.hpp"
#include "serialization.hpp"

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

bool operator==(const ShortPositionVector& lhs, const ShortPositionVector& rhs)
{
    return lhs.gn_addr == rhs.gn_addr
        && lhs.timestamp == rhs.timestamp
        && lhs.latitude == rhs.latitude
        && lhs.longitude == rhs.longitude;
}

bool operator!=(const ShortPositionVector& lhs, const ShortPositionVector& rhs)
{
    return !(lhs == rhs);
}

void serialize(const LongPositionVector& lpv, OutputArchive& ar)
{
    serialize(lpv.gn_addr, ar);
    serialize(lpv.timestamp, ar);
    serialize(lpv.latitude, ar);
    serialize(lpv.longitude, ar);
    uint16_t paiAndSpeed = lpv.speed.value().raw();
    paiAndSpeed |= lpv.position_accuracy_indicator ?  0x8000 : 0x0000;
    serialize(host_cast(paiAndSpeed), ar);
    serialize(lpv.heading, ar);
}

} // namespace geonet
} // namespace vanetza
