#ifndef CHECK_REGION_HPP_UFSV2RZ5
#define CHECK_REGION_HPP_UFSV2RZ5

#include <vanetza/security/region.hpp>

namespace vanetza
{
namespace security
{

void check(const TwoDLocation& expected, const TwoDLocation& actual);
void check(const CircularRegion& expected, const CircularRegion& actual);
void check(const RectangularRegion& expected, const RectangularRegion& actual);
void check(std::list<RectangularRegion> expected, std::list<RectangularRegion> actual);
void check(PolygonalRegion expected, PolygonalRegion actual);
void check(const IdentifiedRegion& expected, const IdentifiedRegion& actual);
void check(const GeographicRegion& expected, const GeographicRegion& actual);

} // namespace security
} // namespace vanetza

#endif /* CHECK_REGION_HPP_UFSV2RZ5 */

