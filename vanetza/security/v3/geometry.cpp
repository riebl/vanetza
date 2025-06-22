#include <vanetza/asn1/security/CircularRegion.h>
#include <vanetza/asn1/security/PolygonalRegion.h>
#include <vanetza/asn1/security/RectangularRegion.h>
#include <vanetza/asn1/security/SequenceOfRectangularRegion.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/boost_geometry.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <vanetza/security/v3/geometry.hpp>
#include <boost/geometry/algorithms/within.hpp>
#include <boost/units/cmath.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool is_valid(const asn1::TwoDLocation& location)
{
    return location.latitude >= Vanetza_Security_NinetyDegreeInt_min &&
        location.latitude <= Vanetza_Security_NinetyDegreeInt_max &&
        location.longitude >= Vanetza_Security_OneEightyDegreeInt_min &&
        location.longitude <= Vanetza_Security_OneEightyDegreeInt_max;
}

bool is_inside(const PositionFix& location, const asn1::CircularRegion& region)
{
    if (is_valid(region.center) && region.radius >= 0) {
        return distance(location, region.center) <= region.radius * units::si::meter;
    } else {
        return false;
    }
}

bool is_inside(const PositionFix& location, const asn1::SequenceOfRectangularRegion& regions)
{
    for (int i = 0; i < regions.list.count; ++i) {
        if (regions.list.array[i] != nullptr && is_inside(location, *regions.list.array[i])) {
            return true;
        }
    }

    return false;
}

bool is_inside(const PositionFix& location, const asn1::RectangularRegion& region)
{
    const bool location_valid = isfinite(location.latitude) && isfinite(location.longitude);
    const bool region_valid = is_valid(region.northWest) && is_valid(region.southEast);
    if (location_valid && region_valid) {
        if (region.northWest.latitude <= region.southEast.latitude) {
            // north-west is equal or south of south-east: invalid region
            return false;
        } else if (region.northWest.longitude == region.southEast.longitude) {
            // equal longitudes are invalid
            return false;
        } else {
            Vanetza_Security_NinetyDegreeInt_t loc_lat = location.latitude / (90.0 * units::degree) * Vanetza_Security_NinetyDegreeInt_max;
            Vanetza_Security_OneEightyDegreeInt_t loc_lon = location.longitude / (180.0 * units::degree) * Vanetza_Security_OneEightyDegreeInt_max;

            if (loc_lat >= region.southEast.latitude && loc_lat <= region.northWest.latitude) {
                if (region.northWest.longitude < region.southEast.longitude) {
                    return loc_lon >= region.northWest.longitude && loc_lon <= region.southEast.longitude;
                } else {
                    return loc_lon >= region.northWest.longitude || loc_lon <= region.southEast.longitude;
                }
            }
        }
    }

    return false;
}

bool is_inside(const asn1::TwoDLocation* location, const asn1::PolygonalRegion* region)
{
    if (region && location) {
        PolygonalRegionRingAdapter polygonal_region(*region);
        auto point = make_model(*location);
        return boost::geometry::within(point, polygonal_region);
    }

    return false;
}

bool is_inside(const PositionFix& location, const asn1::PolygonalRegion& region)
{
    if (isfinite(location.latitude) && isfinite(location.longitude)) {
        PolygonalRegionRingAdapter polygonal_region(region);
        auto point = make_model(location);
        return boost::geometry::within(point, polygonal_region);
    }

    return false;
}

} // namespace v3
} // namespace security
} // namespace vanetza
