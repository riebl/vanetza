#pragma once
#include <vanetza/security/v3/asn1_types.hpp>

namespace vanetza
{

// forward declaration
struct PositionFix;

namespace security
{
namespace v3
{

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

/**
 * \brief Check if a location is inside a polygonal region.
 *
 * \param location The location to check.
 * \param region The polygonal region to check against.
 * \return true if the location is inside the region, false otherwise.
 */
bool is_inside(const PositionFix& location, const asn1::PolygonalRegion& region);
bool is_inside(const asn1::TwoDLocation* location, const asn1::PolygonalRegion* region);

} // namespace v3
} // namespace security
} // namespace vanetza

