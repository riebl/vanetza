#include <gtest/gtest.h>
#include <vanetza/asn1/security/Latitude.h>
#include <vanetza/asn1/security/Longitude.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <boost/units/cmath.hpp>

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
