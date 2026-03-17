#pragma once

#include <vanetza/geodesy/position.hpp>

namespace vanetza
{
namespace geodesy
{
namespace haversine
{

/**
 * Get distance between two geodetic positions using the Haversine formula.
 * Uses a spherical Earth model (radius 6371 km).
 * \param a first position
 * \param b second position
 * \return distance in meters (always positive)
 */
units::Length distance(const GeodeticPosition& a, const GeodeticPosition& b);

/**
 * Derive cartesian position ENU from geodetic coordinates using equirectangular projection.
 * Uses a spherical Earth model (radius 6371 km).
 * Suitable for short distances (< ~10 km) typical in GeoNetworking.
 * \param origin Reference point becoming origin
 * \param position Calculate cartesian coordinates for this point
 * \return Cartesian coordinates of position relative to origin
 */
CartesianPosition local_cartesian(
        const GeodeticPosition& origin,
        const GeodeticPosition& position);

} // namespace haversine
} // namespace geodesy
} // namespace vanetza
