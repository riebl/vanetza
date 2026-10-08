#include <gtest/gtest.h>
#include <vanetza/facilities/spat_functions.hpp>

using namespace vanetza;
using namespace vanetza::facilities;

TEST(SpatFunctions, minute_of_the_year)
{
    EXPECT_EQ(0, minute_of_the_year(Clock::at("2026-01-01 00:00:00")));
    EXPECT_EQ(0, minute_of_the_year(Clock::at("2026-01-01 00:00:59.999")));
    EXPECT_EQ(1, minute_of_the_year(Clock::at("2026-01-01 00:01:00")));
    EXPECT_EQ(525599, minute_of_the_year(Clock::at("2026-12-31 23:59:30")));
    // leap year has one more day
    EXPECT_EQ(527039, minute_of_the_year(Clock::at("2024-12-31 23:59:00")));
    EXPECT_LT(minute_of_the_year(Clock::at("2024-12-31 23:59:59.999")), cMinuteOfTheYearUnknown);
}

TEST(SpatFunctions, dsecond)
{
    EXPECT_EQ(0, dsecond(Clock::at("2026-10-03 10:15:00")));
    EXPECT_EQ(30250, dsecond(Clock::at("2026-10-03 10:15:30.250")));
    EXPECT_EQ(59999, dsecond(Clock::at("2026-10-03 10:15:59.999")));
}

TEST(SpatFunctions, time_mark)
{
    EXPECT_EQ(0, time_mark(Clock::at("2026-10-03 10:00:00")));
    // 15 min 30.25 s -> 9302.5 tenths, truncated
    EXPECT_EQ(9302, time_mark(Clock::at("2026-10-03 10:15:30.250")));
    EXPECT_EQ(35999, time_mark(Clock::at("2026-10-03 10:59:59.999")));
}

TEST(SpatFunctions, time_mark_roundtrip)
{
    const auto at = Clock::at("2026-10-03 10:15:30.200");
    auto resolved = time_mark_to_time_point(time_mark(at), at);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(at, *resolved);
}

TEST(SpatFunctions, time_mark_next_hour)
{
    // forecast 20 s ahead crosses the hour boundary
    const auto now = Clock::at("2026-10-03 10:59:50");
    auto resolved = time_mark_to_time_point(100, now);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:00:10"), *resolved);
}

TEST(SpatFunctions, time_mark_hour_rule)
{
    // C2C-CC RS 2077, RS_ARSM_54: a mark refers to the hour of the reference time,
    // or to the following hour if it is earlier than the begin of the reference minute
    const auto now = Clock::at("2026-10-03 11:00:05");
    auto resolved = time_mark_to_time_point(35950, now);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:59:55"), *resolved);

    // same minute: an earlier mark still belongs to the current hour
    const auto later = Clock::at("2026-10-03 10:15:40");
    resolved = time_mark_to_time_point(9001, later); // xx:15:00.1
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:15:00.100"), *resolved);

    // before the reference minute: following hour
    resolved = time_mark_to_time_point(8999, later); // xx:14:59.9
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:14:59.900"), *resolved);
}

TEST(SpatFunctions, time_mark_special_values)
{
    const auto now = Clock::at("2026-10-03 10:00:00");
    EXPECT_FALSE(time_mark_to_time_point(cTimeMarkUnknown, now));
    EXPECT_FALSE(time_mark_to_time_point(cTimeMarkOutOfRange, now));
    EXPECT_FALSE(time_mark_to_time_point(-1, now));
}

TEST(SpatFunctions, utc_from_tai)
{
    // TAI - UTC: 32 s in 2005, 37 s since 2017
    EXPECT_EQ(Clock::at("2005-06-01 12:00:00"), utc_from_tai(Clock::at("2005-06-01 12:00:32")));
    EXPECT_EQ(Clock::at("2026-10-03 10:00:00"), utc_from_tai(Clock::at("2026-10-03 10:00:37")));
    // first instant after the leap second inserted at the end of 2016
    EXPECT_EQ(Clock::at("2017-01-01 00:00:00"), utc_from_tai(Clock::at("2017-01-01 00:00:37")));
    EXPECT_EQ(Clock::at("2016-12-31 23:59:59"), utc_from_tai(Clock::at("2017-01-01 00:00:35")));
}

TEST(SpatFunctions, time_mark_at_hour_edges)
{
    // minute 0 of the hour: every mark belongs to the current hour
    const auto first_minute = Clock::at("2026-10-03 10:00:30");
    auto resolved = time_mark_to_time_point(0, first_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:00:00"), *resolved);

    // minute 59: only marks of the last minute stay in the current hour
    const auto last_minute = Clock::at("2026-10-03 10:59:30");
    resolved = time_mark_to_time_point(35400, last_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:59:00"), *resolved);
    resolved = time_mark_to_time_point(35399, last_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:58:59.900"), *resolved);
}
