#pragma once

#include <vanetza/geodesy/position.hpp>

namespace vanetza
{
namespace geodesy
{
namespace geographiclib
{

/**
 * Get distance between two geodetic positions on WGS84 ellipsoid using GeographicLib.
 * \param a first position
 * \param b second position
 * \return distance in meters (always positive) or NaN for invalid input
 */
units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b);

/**
 * Derive cartesian position ENU from geodetic WGS84 coordinates using GeographicLib.
 * Uses proper ellipsoidal LocalCartesian projection.
 * \param origin WGS84 reference point becoming origin
 * \param position Calculate cartesian coordinates for this point
 * \return Cartesian coordinates of position relative to origin
 */
CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position);

} // namespace geographiclib
} // namespace geodesy
} // namespace vanetza
