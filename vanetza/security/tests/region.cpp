#include <gtest/gtest.h>
#include <vanetza/security/region.hpp>
#include <vanetza/security/tests/check_region.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>
#include <limits>

using namespace vanetza::security;
using vanetza::geonet::distance_u16t;
using vanetza::geonet::geo_angle_i32t;
using vanetza::units::degrees;
using vanetza::units::si::meter;

TEST(Region, Serialize_CircularRegion)
{
    CircularRegion reg;
    reg.center.latitude = static_cast<geo_angle_i32t>(12564 * degrees);
    reg.center.longitude = static_cast<geo_angle_i32t>(654321 * degrees);
    reg.radius = static_cast<distance_u16t>(1337 * meter);
    check(reg, serialize_roundtrip(reg));
}

TEST(Region, Serialize_IdentifiedRegion)
{
    IdentifiedRegion reg;
    reg.region_dictionary = RegionDictionary::ISO_3166_1;
    reg.region_identifier = 12345;
    reg.local_region.set(546);
    check(reg, serialize_roundtrip(reg));
}

TEST(Region, Serialize_PolygonalRegion)
{
    PolygonalRegion reg;
    for (std::size_t i = 0; i < 3; ++i) {
        reg.push_back(TwoDLocation {
                geo_angle_i32t::from_value(25 + i),
                geo_angle_i32t::from_value(26 + i)
            });
    }
    check(reg, serialize_roundtrip(reg));
}

TEST(Region, Serialize_RectangularRegion_list)
{
    std::list<RectangularRegion> reg;
    for (std::size_t i = 0; i < 5; ++i) {
        reg.push_back(RectangularRegion {
            TwoDLocation {
                geo_angle_i32t::from_value(1000000 + i),
                geo_angle_i32t::from_value(1010000 + i)
            },
            TwoDLocation {
                geo_angle_i32t::from_value(1020000 + i),
                geo_angle_i32t::from_value(1030000 + i)
            }
        });
    }
    check(reg, serialize_roundtrip(reg));
}

TEST(Region, TwoDLocation_Within_Circle)
{
    CircularRegion region;
    region.radius = static_cast<distance_u16t>(400 * meter);
    region.center = TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    EXPECT_TRUE(is_within(region.center, region));

    EXPECT_TRUE(is_within(TwoDLocation {
        geo_angle_i32t::from_value(490143170),
        geo_angle_i32t::from_value(83995470)
    }, region));

    EXPECT_FALSE(is_within(TwoDLocation {
        geo_angle_i32t::from_value(490145910),
        geo_angle_i32t::from_value(83984740)
    }, region));

    EXPECT_FALSE(is_within(TwoDLocation {
        geo_angle_i32t::from_value(490137060),
        geo_angle_i32t::from_value(84120020)
    }, region));
}

TEST(Region, Circle_Within_Circle)
{
    CircularRegion outer;
    outer.radius = static_cast<distance_u16t>(400 * meter);
    outer.center = TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    CircularRegion inner;
    inner.center = outer.center;

    for (int i = 0; i <= 400; i += 10) {
        inner.radius = static_cast<distance_u16t>(i * meter);
        EXPECT_TRUE(is_within(inner, outer));
    }

    inner.radius = static_cast<distance_u16t>(401 * meter);
    EXPECT_FALSE(is_within(inner, outer));

    inner.center = TwoDLocation {
        geo_angle_i32t::from_value(490143170),
        geo_angle_i32t::from_value(83995470)
    };

    inner.radius = static_cast<distance_u16t>(38 * meter);
    EXPECT_TRUE(is_within(inner, outer));

    inner.radius = static_cast<distance_u16t>(40 * meter);
    EXPECT_FALSE(is_within(inner, outer));
}

TEST(Region, TwoDLocation_Within_None)
{
    NoneRegion region;

    EXPECT_TRUE(is_within(TwoDLocation {
        geo_angle_i32t::from_value(490143170),
        geo_angle_i32t::from_value(83995470)
    }, region));
}

TEST(Region, Circle_Within_None)
{
    NoneRegion outer;

    CircularRegion inner;
    inner.radius = static_cast<distance_u16t>(400 * meter);
    inner.center = TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    EXPECT_TRUE(is_within(inner, outer));
    EXPECT_FALSE(is_within(outer, inner));
}

TEST(Region, TwoDLocation_Within_Rectangles)
{
    TwoDLocation northwest {
        static_cast<geo_angle_i32t>(20 * degrees),
        static_cast<geo_angle_i32t>(10 * degrees)
    };
    TwoDLocation southeast {
        static_cast<geo_angle_i32t>(10 * degrees),
        static_cast<geo_angle_i32t>(20 * degrees)
    };
    RectangularRegion region { northwest, southeast };
    std::list<RectangularRegion> regions({ region });

    // inside
    EXPECT_TRUE(is_within(TwoDLocation {
        static_cast<geo_angle_i32t>(15 * degrees),
        static_cast<geo_angle_i32t>(15 * degrees)
    }, regions));

    // outside - left
    EXPECT_FALSE(is_within(TwoDLocation {
        static_cast<geo_angle_i32t>(15 * degrees),
        static_cast<geo_angle_i32t>(9 * degrees)
    }, regions));

    // outside - right
    EXPECT_FALSE(is_within(TwoDLocation {
        static_cast<geo_angle_i32t>(15 * degrees),
        static_cast<geo_angle_i32t>(21 * degrees)
    }, regions));

    // outside - top
    EXPECT_FALSE(is_within(TwoDLocation {
        static_cast<geo_angle_i32t>(21 * degrees),
        static_cast<geo_angle_i32t>(15 * degrees)
    }, regions));

    // outside - down
    EXPECT_FALSE(is_within(TwoDLocation {
        static_cast<geo_angle_i32t>(9 * degrees),
        static_cast<geo_angle_i32t>(15 * degrees)
    }, regions));
}

TEST(Region, Rectangles_Within_None)
{
    TwoDLocation northwest {
        static_cast<geo_angle_i32t>(20 * degrees),
        static_cast<geo_angle_i32t>(10 * degrees)
    };
    TwoDLocation southeast {
        static_cast<geo_angle_i32t>(10 * degrees),
        static_cast<geo_angle_i32t>(20 * degrees)
    };
    RectangularRegion region { northwest, southeast };
    std::list<RectangularRegion> regions({ region });

    EXPECT_TRUE(is_within(regions, NoneRegion()));
    EXPECT_FALSE(is_within(NoneRegion(), regions));
}

TEST(Region, Rectangle_Within_Rectangle_Exact)
{
    TwoDLocation northwest_a {
        static_cast<geo_angle_i32t>(10 * degrees),
        static_cast<geo_angle_i32t>(10 * degrees)
    };
    TwoDLocation southeast_a {
        static_cast<geo_angle_i32t>(20 * degrees),
        static_cast<geo_angle_i32t>(20 * degrees)
    };

    TwoDLocation northwest_b {
        static_cast<geo_angle_i32t>(10 * degrees),
        static_cast<geo_angle_i32t>(10 * degrees)
    };
    TwoDLocation southeast_b {
        static_cast<geo_angle_i32t>(20 * degrees),
        static_cast<geo_angle_i32t>(20 * degrees)
    };

    RectangularRegion a { northwest_a, southeast_a };
    RectangularRegion b { northwest_b, southeast_b };

    std::list<RectangularRegion> region_a({ a });
    std::list<RectangularRegion> region_b({ b });

    EXPECT_TRUE(is_within(region_a, region_b));
    EXPECT_TRUE(is_within(region_b, region_a));
}

TEST(Region, Altitude_To_Elevation)
{
    using Elevation = ThreeDLocation::Elevation;

    auto altitude_empty = std::numeric_limits<double>::quiet_NaN() * meter;
    EXPECT_EQ(to_elevation(altitude_empty), ThreeDLocation::unknown_elevation);

    auto altitude_positive = 2843.6 * meter;
    EXPECT_EQ(to_elevation(altitude_positive), (Elevation { 0x6F, 0x14 }));

    auto altitude_negative = -170.2 * meter;
    EXPECT_EQ(to_elevation(altitude_negative), (Elevation { 0xF9, 0x5A }));

    auto altitude_below_min = -420.0 * meter;
    EXPECT_EQ(to_elevation(altitude_below_min), ThreeDLocation::min_elevation);

    auto altitude_above_max = 6150.0 * meter;
    EXPECT_EQ(to_elevation(altitude_above_max), ThreeDLocation::max_elevation);

    // examples given in TS 103 097 V1.2.1 (section 4.2.19)
    EXPECT_EQ(to_elevation(0.0 * meter), (Elevation { 0x00, 0x00 }));
    EXPECT_EQ(to_elevation(100.0 * meter), (Elevation { 0x03, 0xe8 }));
    EXPECT_EQ(to_elevation(-209.5 * meter), (Elevation { 0xf7, 0xd1 }));
}
