#include <gtest/gtest.h>
#include <vanetza/facilities/cam_functions.hpp>

using namespace vanetza;
using namespace vanetza::facilities;
using namespace vanetza::units;

TEST(CamFunctions, similar_heading)
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

TEST(CamFunctions, similar_heading_unavailable1)
{
    Heading a;
    a.headingValue = HeadingValue_unavailable;
    Angle b = 2.0 * si::radian;
    Angle limit = 10 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));

    a.headingValue = 2 * HeadingValue_wgs84East;
    EXPECT_TRUE(similar_heading(a, b, limit));

    b = 0.0 * si::radian;
    limit = 3.14 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));

    limit = 3.15 * si::radian;
    EXPECT_TRUE(similar_heading(a, b, limit));
}

TEST(CamFunctions, similar_heading_unavailable2)
{
    Heading a;
    a.headingValue = HeadingValue_unavailable;
    Heading b;
    b.headingValue = HeadingValue_unavailable;
    Angle limit = 10 * si::radian;
    EXPECT_FALSE(similar_heading(a, b, limit));

    b.headingValue = 200;
    EXPECT_FALSE(similar_heading(a, b, limit));
    EXPECT_FALSE(similar_heading(b, a, limit));

    a.headingValue = 300;
    EXPECT_TRUE(similar_heading(a, b, limit));
    EXPECT_TRUE(similar_heading(b, a, limit));
}
