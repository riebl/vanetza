#include <vanetza/geodesy/geographiclib.hpp>
#include <GeographicLib/Geocentric.hpp>
#include <GeographicLib/Geodesic.hpp>
#include <GeographicLib/LocalCartesian.hpp>
#include <limits>

namespace vanetza
{
namespace geodesy
{
namespace geographiclib
{

units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b)
{
    const auto& geod = GeographicLib::Geodesic::WGS84();
    double distance_m = 0.0;
    geod.Inverse(a.latitude / units::degree, a.longitude / units::degree,
            b.latitude / units::degree, b.longitude / units::degree,
            distance_m);
    return (distance_m >= 0.0 ? distance_m : std::numeric_limits<double>::quiet_NaN()) * units::si::meter;
}

CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position)
{
    const auto& earth = GeographicLib::Geocentric::WGS84();
    GeographicLib::LocalCartesian proj {
            origin.latitude / units::degree,
            origin.longitude / units::degree,
            0.0, earth
    };
    double result_x, result_y, unused_z = 0.0;
    proj.Forward(position.latitude / units::degree,
            position.longitude / units::degree, 0.0,
            result_x, result_y, unused_z);
    return CartesianPosition(result_x * units::si::meter, result_y * units::si::meter);
}

} // namespace geographiclib
} // namespace geodesy
} // namespace vanetza
