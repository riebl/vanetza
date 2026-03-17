#include "areas.hpp"
#include <boost/math/constants/constants.hpp>
#include <boost/units/cmath.hpp>
#include <algorithm>
#include <cassert>
#include <limits>

namespace vanetza
{
namespace geonet
{

double geometric_function(const Circle& c, const CartesianPosition& p)
{
    if (c.r.value() != 0.0) {
        const double x_over_r = p.x / c.r;
        const double y_over_r = p.y / c.r;
        return 1.0 - (x_over_r * x_over_r) - (y_over_r * y_over_r);
    } else {
        return -std::numeric_limits<double>::infinity();
    };
}

double geometric_function(const Rectangle& r, const CartesianPosition& p)
{
    if (r.a.value() != 0.0 && r.b.value() != 0.0) {
        const double x_over_a = p.x / r.a;
        const double y_over_b = p.y / r.b;
        return std::min(1.0 - x_over_a * x_over_a, 1.0 - y_over_b * y_over_b);
    } else {
        return -std::numeric_limits<double>::infinity();
    }
}

double geometric_function(const Ellipse& e, const CartesianPosition& p)
{
    if (e.a.value() != 0.0 && e.b.value() != 0.0) {
        const double x_over_a = p.x / e.a;
        const double y_over_b = p.y / e.b;
        return 1.0 - (x_over_a * x_over_a) - (y_over_b * y_over_b);
    } else {
        return -std::numeric_limits<double>::infinity();
    }
}

struct geometric_function_visitor : public boost::static_visitor<double>
{
    geometric_function_visitor(const CartesianPosition& p) : point(p) {}

    template<class SHAPE>
    double operator()(const SHAPE& s) const
    {
        return geometric_function(s, point);
    }

    const CartesianPosition& point;
};

double geometric_function(const decltype(Area::shape)& shape, const CartesianPosition& p)
{
    geometric_function_visitor visitor(p);
    return boost::apply_visitor(visitor, shape);
}

CartesianPosition canonicalize(const CartesianPosition& point, units::Angle azimuth)
{
    using namespace boost::math::double_constants;
    // area.angle is azimuth angle of EN 302 931 V1.1.1
    const units::Angle zenith = half_pi * units::si::radian - azimuth;
    const double sin_z = sin(zenith);
    const double cos_z = cos(zenith);
    // rotate canonical point around origin clockwise: zenith = 90 deg - azimuth
    // other interpretation: rotate shape's long side onto abscissa
    CartesianPosition canonical;
    canonical.x = cos_z * point.x + sin_z * point.y;
    canonical.y = -sin_z * point.x + cos_z * point.y;
    return canonical;
}

struct area_size_visitor : public boost::static_visitor<units::Area>
{
    units::Area operator()(const Circle& circle) const
    {
        using namespace boost::math::double_constants;
        return pi * circle.r * circle.r;
    }

    units::Area operator()(const Rectangle& rectangle) const
    {
        using namespace boost::math::double_constants;
        return 4.0 * rectangle.a * rectangle.b;
    }

    units::Area operator()(const Ellipse& ellipse) const
    {
        using namespace boost::math::double_constants;
        return pi * ellipse.a * ellipse.b;
    }
};

units::Area area_size(const Area& area)
{
    return boost::apply_visitor(area_size_visitor(), area.shape);
}

bool inside_or_at_border(const Area& area, const GeodeticPosition& geo_position)
{
    const CartesianPosition local = local_cartesian(area.position, geo_position);
    const CartesianPosition canonical = canonicalize(local, area.angle);
    return !outside_shape(area.shape, canonical);
}

} // namespace geonet
} // namespace vanetza

