#pragma once

#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

namespace vanetza
{
namespace geodesy
{

/**
 * Cartesian position.
 * Point in an ENU (East-North-Up) coordinate system, units in meters.
 */
struct CartesianPosition
{
    CartesianPosition() : x(0.0 * units::si::meter), y(0.0 * units::si::meter) {}
    CartesianPosition(units::Length x_, units::Length y_) : x(x_), y(y_) {}
    units::Length x;
    units::Length y;
};

CartesianPosition operator-(const CartesianPosition&, const CartesianPosition&);

struct GeodeticPosition
{
    GeodeticPosition() :
        latitude(0.0 * units::degree), longitude(0.0 * units::degree) {}
    GeodeticPosition(units::GeoAngle lat, units::GeoAngle lon) :
        latitude(lat), longitude(lon) {}
    units::GeoAngle latitude;
    units::GeoAngle longitude;
};

} // namespace geodesy
} // namespace vanetza
