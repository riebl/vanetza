#include <vanetza/common/position_fix.hpp>
#include <vanetza/asn1/security/Latitude.h>
#include <vanetza/asn1/security/Longitude.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/security/v3/distance.hpp>
#include <boost/units/cmath.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

units::Length distance(const PositionFix& one, const asn1::TwoDLocation& other)
{
    static const auto earth_radius = 6371000.0 * units::si::meter;
    const auto other_lat = convert_latitude(other.latitude);
    const auto other_lon = convert_longitude(other.longitude);
    const units::Angle delta_phi { one.latitude - other_lat };
    const units::Angle delta_lambda { one.longitude - other_lon };
    const auto sin_delta_phi = sin(delta_phi / 2.0);
    const auto sin_delta_lambda = sin(delta_lambda / 2.0);
    const auto a = sin_delta_phi * sin_delta_phi +
        cos(one.latitude) * cos(other_lat) * sin_delta_lambda * sin_delta_lambda;
    const auto c = 2.0 * atan2(sqrt(a), sqrt(1 - a));
    return earth_radius * c;
}

units::GeoAngle convert_latitude(const asn1::Latitude& in)
{
    if (in >= Vanetza_Security_NinetyDegreeInt_min && in <= Vanetza_Security_NinetyDegreeInt_max) {
        return in * 90.0 / Vanetza_Security_NinetyDegreeInt_max * units::degree;
    } else {
        return units::GeoAngle::from_value(std::numeric_limits<double>::quiet_NaN());
    }
}

units::GeoAngle convert_longitude(const asn1::Longitude& in)
{
    if (in >= Vanetza_Security_OneEightyDegreeInt_min && in <= Vanetza_Security_OneEightyDegreeInt_max) {
        return in * 180.0 / Vanetza_Security_OneEightyDegreeInt_max * units::degree;
    } else {
        return units::GeoAngle::from_value(std::numeric_limits<double>::quiet_NaN());
    }
}

} // namespace v3
} // namespace security
} // namespace vanetza
