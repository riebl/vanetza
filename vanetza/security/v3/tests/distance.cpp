#include <gtest/gtest.h>
#include <vanetza/asn1/security/CircularRegion.h>
#include <vanetza/asn1/security/Latitude.h>
#include <vanetza/asn1/security/Longitude.h>
#include <vanetza/asn1/security/RectangularRegion.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <boost/units/cmath.hpp>
#include <utility>

using namespace vanetza::security::v3;
namespace units = vanetza::units;

namespace boost {
namespace units {

void PrintTo(const vanetza::units::Length& l, std::ostream* out)
{
    *out << l.value() << " m";
}

void PrintTo(const vanetza::units::GeoAngle& a, std::ostream* out)
{
    *out << a.value() << " deg";
}

} // namespace units
} // namespace boost

#define EXPECT_ANGLE_EQ(a, b) { \
    double a_value = units::GeoAngle { a }.value(); \
    double b_value = units::GeoAngle { b }.value(); \
    EXPECT_NEAR(a_value, b_value, 1e-6); \
}

#define EXPECT_LENGTH_EQ(a, b) { \
    double a_value = units::Length { a }.value(); \
    double b_value = units::Length { b }.value(); \
    EXPECT_NEAR(a_value, b_value, 1.0); \
}

TEST(Distance, distance)
{
    vanetza::PositionFix one;
    one.latitude = 48.0 * units::degree;
    one.longitude = 11.0 * units::degree;

    asn1::TwoDLocation other;
    other.latitude = 480000000;
    other.longitude = 110000000;
    EXPECT_LENGTH_EQ(distance(one, other), 0.0 * units::si::meter);

    other.latitude = 481234000;
    other.longitude = 109876000;
    EXPECT_LENGTH_EQ(distance(one, other), 13752.4 * units::si::meter);
}

TEST(Distance, convert_latitude)
{
    EXPECT_ANGLE_EQ(convert_latitude(Vanetza_Security_NinetyDegreeInt_min), -90.0 * units::degree);
    EXPECT_ANGLE_EQ(convert_latitude(Vanetza_Security_NinetyDegreeInt_max), 90 * units::degree);
    EXPECT_ANGLE_EQ(convert_latitude(0), 0 * units::degree);
    EXPECT_FALSE(boost::units::isfinite(convert_latitude(Vanetza_Security_NinetyDegreeInt_unknown)));
}

TEST(Distance, convert_longitude)
{
    EXPECT_ANGLE_EQ(convert_longitude(Vanetza_Security_OneEightyDegreeInt_min), -179.999999 * units::degree);
    EXPECT_ANGLE_EQ(convert_longitude(Vanetza_Security_OneEightyDegreeInt_max), 180 * units::degree);
    EXPECT_ANGLE_EQ(convert_longitude(0), 0 * units::degree);
    EXPECT_FALSE(boost::units::isfinite(convert_longitude(Vanetza_Security_OneEightyDegreeInt_unknown)));
}

TEST(Distance, location_is_valid)
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

TEST(Distance, is_inside_circular)
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

TEST(Distance, is_inside_rectangular)
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
