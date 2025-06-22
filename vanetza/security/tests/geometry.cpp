#include <gtest/gtest.h>
#include <vanetza/asn1/security/CircularRegion.h>
#include <vanetza/asn1/security/PolygonalRegion.h>
#include <vanetza/asn1/security/RectangularRegion.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/geometry.hpp>
#include <vanetza/units/angle.hpp>
#include <array>

using namespace vanetza::security::v3;
namespace units = vanetza::units;

TEST(Geometry, location_is_valid)
{
    asn1::TwoDLocation location;
    location.latitude = Vanetza_Security_NinetyDegreeInt_unknown;
    location.longitude = Vanetza_Security_OneEightyDegreeInt_unknown;
    EXPECT_FALSE(is_valid(location));

    location.latitude = 0;
    EXPECT_FALSE(is_valid(location));

    location.longitude = 0;
    EXPECT_TRUE(is_valid(location));
}

TEST(Geometry, is_inside_circular)
{
    vanetza::PositionFix fix;
    fix.latitude = 48.0 * units::degree;
    fix.longitude = 11.0 * units::degree;

    asn1::CircularRegion region;
    region.center.latitude = 480010000; /*< 1 degree equals 111km */
    region.center.longitude = 110000000;

    region.radius = 100; /*< 100 is not enough */
    EXPECT_FALSE(is_inside(fix, region));

    region.radius = 120; /*< 120 exceeds 111m */
    EXPECT_TRUE(is_inside(fix, region));
}

TEST(Geometry, is_inside_rectangular)
{
    asn1::RectangularRegion region;
    region.northWest.latitude = 485000000;
    region.northWest.longitude = 110000000;
    region.southEast.latitude = 480000000;
    region.southEast.longitude = 115000000;

    auto build_posfix = [](double lat, double lon) {
        vanetza::PositionFix fix;
        fix.latitude = lat * units::degree;
        fix.longitude = lon * units::degree;
        return fix;
    };

    EXPECT_TRUE(is_inside(build_posfix(48.001, 11.001), region));
    EXPECT_FALSE(is_inside(build_posfix(47.999, 11.001), region));
    EXPECT_FALSE(is_inside(build_posfix(48.501, 11.001), region));
    EXPECT_FALSE(is_inside(build_posfix(48.001, 10.999), region));
    EXPECT_FALSE(is_inside(build_posfix(48.001, 11.501), region));

    std::swap(region.northWest, region.southEast);
    EXPECT_FALSE(is_inside(build_posfix(48.001, 11.001), region));
}

TEST(Geometry, is_inside_polygon)
{
    asn1::PolygonalRegion region;
    std::array<asn1::TwoDLocation, 4> locations = {{
        { 100000000, 0 },
        { 100000000, 100000000 },
        { 0, 100000000 },
        { 0, 0}
    }};
    std::array<asn1::TwoDLocation*, 4> location_ptrs = {
        &locations[0], &locations[1], &locations[2], &locations[3]
    };
    region.list.array = location_ptrs.data();
    region.list.count = location_ptrs.size();
    region.list.size = location_ptrs.size();

    asn1::TwoDLocation point_b = { -10000000, -10000000 };
    EXPECT_FALSE(is_inside(&point_b, &region));

    asn1::TwoDLocation point_a = { 50000000, 50000000 };
    EXPECT_TRUE(is_inside(&point_a, &region));

    // also reversed order of region points
    location_ptrs = { &locations[3], &locations[2], &locations[1], &locations[0] };
    EXPECT_TRUE(is_inside(&point_a, &region));

    vanetza::PositionFix fix;
    fix.latitude = -1 * units::degree;
    fix.longitude = -1 * units::degree;
    EXPECT_FALSE(is_inside(fix, region));

    fix.latitude = 5 * units::degree;
    fix.longitude = 5 * units::degree;
    EXPECT_TRUE(is_inside(fix, region));
}
