#pragma once
#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

namespace vanetza
{

// forward declaration
struct PositionFix;

namespace security
{
namespace v3
{

/**
 * Calculate distance between two positions using Haversine formula
 * 
 * \param one a local position fix
 * \param other a received location
 * \return distance in meters
 */
units::Length distance(const PositionFix& one, const asn1::TwoDLocation& other);

/**
 * Convert ASN.1 latitude to GeoAngle
 * 
 * \param in ASN.1 security latitude
 * \return GeoAngle
 */
units::GeoAngle convert_latitude(const asn1::Latitude& in);

/**
 * Convert ASN.1 longitude to GeoAngle
 * 
 * \param in ASN.1 security longitude
 * \return GeoAngle
 */
units::GeoAngle convert_longitude(const asn1::Longitude& in);

/**
 * Check if a TwoDLocation is valid
 * 
 * \param location TwoDLocation to be checked
 * \return true if latitude and longitude are within valid range
 */
bool is_valid(const asn1::TwoDLocation& location);

/**
 * Check if position is inside a circular region
 * 
 * \param pos position to be checked
 * \param region circular region
 * \return true if position is inside region
 */
bool is_inside(const PositionFix& pos, const asn1::CircularRegion& region);

/**
 * Check if position is inside at least one of the given regions
 * 
 * \param pos position to be checked
 * \param regions sequence of rectangular regions
 * \return true if position is inside at least one region
 */
bool is_inside(const PositionFix& pos, const asn1::SequenceOfRectangularRegion& region);

/**
 * Check if position is inside a rectangular region
 * 
 * \param pos position to be checked
 * \param region rectangular region
 * \return true if position is inside region
 */
bool is_inside(const PositionFix& pos, const asn1::RectangularRegion& region);

} // namespace v3
} // namespace security
} // namespace vanetza
