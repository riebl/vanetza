#include <vanetza/geodesy/geodesy.hpp>
#ifdef VANETZA_WITH_GEOGRAPHICLIB
#   include <vanetza/geodesy/geographiclib.hpp>
#else
#   include <vanetza/geodesy/haversine.hpp>
#endif

namespace vanetza
{
namespace geodesy
{

CartesianPosition operator-(const CartesianPosition& a, const CartesianPosition& b)
{
    return CartesianPosition { a.x - b.x, a.y - b.y };
}

units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b)
{
#ifdef VANETZA_WITH_GEOGRAPHICLIB
    return geographiclib::distance(a, b);
#else
    return haversine::distance(a, b);
#endif
}

CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position)
{
#ifdef VANETZA_WITH_GEOGRAPHICLIB
    return geographiclib::local_cartesian(origin, position);
#else
    return haversine::local_cartesian(origin, position);
#endif
}

} // namespace geodesy
} // namespace vanetza
