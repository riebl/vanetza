#include <vanetza/geodesy/haversine.hpp>
#include <boost/units/cmath.hpp>
#include <cmath>
#include <limits>

namespace vanetza
{
namespace geodesy
{
namespace haversine
{

// arithmetic mean radius of WGS84 ellipsoid
static const units::Length earth_radius = 6371008.8 * units::si::meter;

units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b)
{
    using boost::units::sin;
    using boost::units::cos;

    const units::Angle delta_phi { b.latitude - a.latitude };
    const units::Angle delta_lambda { b.longitude - a.longitude };

    const auto sin_dphi = sin(delta_phi / 2.0);
    const auto sin_dlambda = sin(delta_lambda / 2.0);
    const auto h = sin_dphi * sin_dphi + cos(a.latitude) * cos(b.latitude) * sin_dlambda * sin_dlambda;
    const auto c = 2.0 * std::atan2(std::sqrt(h), std::sqrt(1.0 - h));

    return earth_radius * c;
}

CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position)
{
    using boost::units::cos;

    const double dlat = units::Angle {position.latitude - origin.latitude }.value();
    const double dlon = units::Angle {position.longitude - origin.longitude }.value();

    const units::Length x = dlon * cos(origin.latitude) * earth_radius;
    const units::Length y = dlat * earth_radius;

    return CartesianPosition(x, y);
}

} // namespace haversine
} // namespace geodesy
} // namespace vanetza
