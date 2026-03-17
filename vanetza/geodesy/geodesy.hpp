#pragma once

#include <vanetza/geodesy/position.hpp>

namespace vanetza
{
namespace geodesy
{

/**
 * Get distance between two geodetic positions.
 * Delegates to the best available backend (GeographicLib if available, else haversine).
 * \param a first position
 * \param b second position
 * \return distance in meters (always positive) or NaN for invalid input
 */
units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b);

/**
 * Derive cartesian position ENU from geodetic WGS84 coordinates
 * and a WGS84 reference point which becomes the cartesian origin.
 * Delegates to the best available backend.
 * \param origin WGS84 reference point becoming origin
 * \param position Calculate cartesian coordinates for this point
 * \return Cartesian coordinates of position relative to origin
 */
CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position);

} // namespace geodesy
} // namespace vanetza
