#include <gtest/gtest.h>
#include <vanetza/facilities/path_history.hpp>
#include <vanetza/asn1/its/Heading.h>
#include <vanetza/asn1/its/PathHistory.h>
#include <vanetza/asn1/its/ReferencePosition.h>
#include <vanetza/asn1/its/r2/Heading.h>
#include <vanetza/asn1/its/r2/PathHistory.h>
#include <vanetza/asn1/its/r2/ReferencePosition.h>
#include <vanetza/facilities/cam_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/io.hpp>
#include <cmath>

using namespace vanetza;
using namespace vanetza::facilities;
using namespace vanetza::units;

constexpr long latitude(double degree, double arc_minute)
{
    return std::round(1e7 * (degree + arc_minute / 60.0));
}

constexpr long longitude(double degree, double arc_minute)
{
    return std::round(1e7 * (degree + arc_minute / 60.0));
}

::testing::AssertionResult NearDistance(const Length& a, const Length& b, Length delta)
{
    using namespace boost::units;
    const auto diff = abs(a - b);
    if (diff < delta) {
        return ::testing::AssertionSuccess();
    } else {
        return ::testing::AssertionFailure() << "actual difference " << diff << " exceeds delta of " << delta;
    }
}

using HeadingTypes = ::testing::Types<Heading, Vanetza_ITS2_Heading>;
template<typename T>
class CamFunctionsHeading : public ::testing::Test
{
};
TYPED_TEST_SUITE(CamFunctionsHeading, HeadingTypes);

TEST(CamFunctionsHeading, similar_heading)
{
    Angle a = 3 * si::radian;
    Angle b = 2 * si::radian;
    Angle limit = 0.5 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));
    EXPECT_FALSE(similar_heading(b, a, limit));

    limit = 1.0 * si::radian;
    EXPECT_TRUE(similar_heading(a, b, limit));
    EXPECT_TRUE(similar_heading(b, a, limit));

    a = 6.1 * si::radian;
    b = 0.2 * si::radian;
    limit = 0.4 * si::radian;
    EXPECT_TRUE(similar_heading(a, b, limit));
    EXPECT_TRUE(similar_heading(b, a, limit));

    limit = 0.3 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));
    EXPECT_FALSE(similar_heading(b, a, limit));

    limit = -1.0 * si::radian;
    EXPECT_FALSE(similar_heading(a, a, limit));
}

TYPED_TEST(CamFunctionsHeading, similar_heading_unavailable1)
{
    using SomeHeading = TypeParam;

    SomeHeading a;
    a.headingValue = HeadingValue_unavailable;
    Angle b = 2.0 * si::radian;
    Angle limit = 10 * si::radian;
    EXPECT_FALSE(is_available(a));
    EXPECT_FALSE(similar_heading(a, b, limit));

    a.headingValue = 2 * HeadingValue_wgs84East;
    EXPECT_TRUE(is_available(a));
    EXPECT_TRUE(similar_heading(a, b, limit));

    b = 0.0 * si::radian;
    limit = 3.14 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));

    limit = 3.15 * si::radian;
    EXPECT_TRUE(similar_heading(a, b, limit));
}

TYPED_TEST(CamFunctionsHeading, similar_heading_unavailable2)
{
    using SomeHeading = TypeParam;

    SomeHeading a;
    a.headingValue = HeadingValue_unavailable;
    SomeHeading b;
    b.headingValue = HeadingValue_unavailable;
    Angle limit = 10 * si::radian;
    EXPECT_FALSE(is_available(a));
    EXPECT_FALSE(is_available(b));
    EXPECT_FALSE(similar_heading(a, b, limit));

    b.headingValue = 200;
    EXPECT_TRUE(is_available(b));
    EXPECT_FALSE(similar_heading(a, b, limit));
    EXPECT_FALSE(similar_heading(b, a, limit));

    a.headingValue = 300;
    EXPECT_TRUE(is_available(a));
    EXPECT_TRUE(similar_heading(a, b, limit));
    EXPECT_TRUE(similar_heading(b, a, limit));
}

using ReferencePositionTypes = ::testing::Types<ReferencePosition_t, Vanetza_ITS2_ReferencePosition_t>;
template<typename T>
class CamFunctionsReferencePosition : public ::testing::Test
{
};
TYPED_TEST_SUITE(CamFunctionsReferencePosition, ReferencePositionTypes);

TYPED_TEST(CamFunctionsReferencePosition, distance_reference_positions)
{
    using SomeReferencePosition = TypeParam;

    SomeReferencePosition pos1;
    pos1.latitude = -latitude(6, 21.23);
    pos1.longitude = -longitude(33, 22.12);
    SomeReferencePosition pos2;
    pos2.latitude = -latitude(6, 22.48);
    pos2.longitude = -longitude(33, 22.55);
    EXPECT_TRUE(NearDistance(distance(pos1, pos2), 2440.0 * si::meter , 10.0 * si::meter));

    SomeReferencePosition pos3;
    pos3.latitude = latitude(37, 17.3);
    pos3.longitude = -longitude(0, 13.14);
    SomeReferencePosition pos4;
    pos4.latitude = latitude(37, 17.19);
    pos4.longitude = longitude(0, 9.45);
    EXPECT_TRUE(NearDistance(distance(pos3, pos4), 33390.0 * si::meter , 100.0 * si::meter));

    SomeReferencePosition pos5;
    pos5.latitude = -latitude(0, 19.24);
    pos5.longitude = longitude(83, 37.32);
    SomeReferencePosition pos6;
    pos6.latitude = latitude(0, 27.15);
    pos6.longitude = longitude(83, 04.45);
    EXPECT_TRUE(NearDistance(distance(pos5, pos6), 105010.0 * si::meter , 300.0 * si::meter));

    SomeReferencePosition pos7;
    pos7.latitude = latitude(48, 45.56);
    pos7.longitude = longitude(11, 26.01);
    SomeReferencePosition pos8;
    pos8.latitude = latitude(48, 45.566);
    pos8.longitude = longitude(11, 26.04);
    EXPECT_TRUE(NearDistance(distance(pos7, pos8), 38.0 * si::meter , 0.5 * si::meter));
}

TYPED_TEST(CamFunctionsReferencePosition, distance_refpos_latlon)
{
    using SomeReferencePosition = TypeParam;

    SomeReferencePosition refpos;
    refpos.latitude = -latitude(6, 21.23);
    refpos.longitude = -longitude(33, 22.12);
    GeoAngle lat = -(6 + (22.48 / 60.0)) * degree;
    GeoAngle lon = -(33 + (22.55 / 60.0)) * degree;
    EXPECT_TRUE(NearDistance(distance(refpos, lat, lon), 2440.0 * si::meter , 10.0 * si::meter));
}

TYPED_TEST(CamFunctionsReferencePosition, distance_unavailable)
{
    using SomeReferencePosition = TypeParam;

    SomeReferencePosition pos1 {};
    SomeReferencePosition pos2 {};
    EXPECT_TRUE(is_available(pos1));
    EXPECT_TRUE(is_available(pos2));
    EXPECT_FALSE(std::isnan(distance(pos1, pos2).value()));

    pos1.latitude = Latitude_unavailable;
    EXPECT_FALSE(is_available(pos1));
    EXPECT_TRUE(std::isnan(distance(pos1, pos2).value()));
    EXPECT_TRUE(std::isnan(distance(pos2, pos1).value()));

    pos1.latitude = 0;
    pos1.longitude = Longitude_unavailable;
    EXPECT_FALSE(is_available(pos1));
    EXPECT_TRUE(std::isnan(distance(pos1, pos2).value()));
    EXPECT_TRUE(std::isnan(distance(pos2, pos1).value()));
}

TYPED_TEST(CamFunctionsReferencePosition, copy)
{
    using SomeReferencePosition = TypeParam;

    PositionFix src;
    src.latitude = 1.23 * vanetza::units::degree;
    src.longitude = 4.56 * vanetza::units::degree;
    src.confidence.orientation = vanetza::units::TrueNorth::from_value(10.0);
    src.confidence.semi_major = 20 * vanetza::units::si::meter;
    src.confidence.semi_minor = 15 * vanetza::units::si::meter;

    SomeReferencePosition dest;
    copy(src, dest);

    EXPECT_EQ(dest.latitude, 123 * 100000);
    EXPECT_EQ(dest.longitude, 456 * 100000);
    EXPECT_EQ(dest.positionConfidenceEllipse.semiMajorConfidence, 20 * 100);
    EXPECT_EQ(dest.positionConfidenceEllipse.semiMinorConfidence, 15 * 100);
    EXPECT_EQ(dest.positionConfidenceEllipse.semiMajorOrientation, 10 * 10);
    EXPECT_EQ(dest.altitude.altitudeValue, AltitudeValue_unavailable);
    EXPECT_EQ(dest.altitude.altitudeConfidence, AltitudeConfidence_unavailable);
}

using PathHistoryTypes = ::testing::Types<::PathHistory, Vanetza_ITS2_PathHistory>;
template<typename T>
class CamFunctionsPathHistory : public ::testing::Test
{
protected:
    vanetza::facilities::PathHistory path_history;

    void add_sample(double lat, double lon, const std::string& time)
    {
        vanetza::facilities::PathPoint path_point;
        path_point.latitude = lat * degree;
        path_point.longitude = lon * degree;
        path_point.time = boost::posix_time::from_iso_string(time);
        path_history.addSample(path_point);
    }
};
TYPED_TEST_SUITE(CamFunctionsPathHistory, PathHistoryTypes);

TYPED_TEST(CamFunctionsPathHistory, copy_path_history)
{
    using SomePathHistory = TypeParam;

    this->add_sample(40.906, 29.155, "20241027T031000");
    this->add_sample(40.907, 29.156, "20241027T031010");
    this->add_sample(40.908, 29.157, "20241027T031020");

    SomePathHistory dest_path_history = {}; // zero-initialize struct
    copy(this->path_history, dest_path_history);
    
    int size = dest_path_history.list.count;
    EXPECT_EQ(size, 2);
    for (int i = 0; i < size; i++) {
        auto current_path_point = dest_path_history.list.array[i];
        ASSERT_NE(current_path_point->pathDeltaTime, nullptr);

        // check ASN.1 constraints
        EXPECT_GE(*current_path_point->pathDeltaTime, 1);
        EXPECT_LE(*current_path_point->pathDeltaTime, 65535);
        EXPECT_GE(current_path_point->pathPosition.deltaLatitude, -131071);
        EXPECT_LE(current_path_point->pathPosition.deltaLatitude, 131072);
        EXPECT_GE(current_path_point->pathPosition.deltaLongitude, -131071);
        EXPECT_LE(current_path_point->pathPosition.deltaLongitude, 131072);
        EXPECT_GE(current_path_point->pathPosition.deltaAltitude, -12700);
        EXPECT_LE(current_path_point->pathPosition.deltaAltitude, 12800);
    }
}
