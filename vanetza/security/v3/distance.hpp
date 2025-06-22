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

} // namespace v3
} // namespace security
} // namespace vanetza
