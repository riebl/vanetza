#include "time.hpp"
#include <vanetza/common/clock.hpp>
#include <boost/date_time/posix_time/posix_time_io.hpp>
#include <boost/optional/optional_io.hpp>
#include <gtest/gtest.h>

using namespace vanetza::pki;

TEST(Time, utc_tai_offset)
{
    using boost::gregorian::date;
    using boost::posix_time::ptime;
    using boost::posix_time::seconds;
    using boost::posix_time::time_duration;

    EXPECT_EQ(37, utc_tai_offset(ptime { date { 2021, 4, 30 } }).seconds());
    EXPECT_EQ(10, utc_tai_offset(ptime { date { 1972, 6, 30 } }).seconds());
    EXPECT_EQ(11, utc_tai_offset(ptime { date { 1972, 7, 1 } }).seconds());

    // Last regular UTC second of the leap day still uses the old offset.
    EXPECT_EQ(10, utc_tai_offset(ptime { date { 1972, 6, 30 }, time_duration { 23, 59, 59 } }).seconds());
    // Offset at the ITS epoch must be 32 for current_time() to be correct.
    EXPECT_EQ(32, utc_tai_offset(vanetza::Clock::epoch()).seconds());
}

TEST(Time, parse_duration_hours_units)
{
    using std::chrono::hours;
    auto h = [](const char* s) {
        auto r = parse_duration_hours(s);
        EXPECT_TRUE(r) << "expected to parse '" << s << "'";
        return r ? r->count() : -1;
    };

    EXPECT_EQ(7, h("7h"));
    EXPECT_EQ(168, h("168h"));
    EXPECT_EQ(24, h("1d"));
    EXPECT_EQ(168, h("1w"));
    EXPECT_EQ(336, h("2w"));

    // m/s collapse to whole hours by truncation
    EXPECT_EQ(2, h("120m"));
    EXPECT_EQ(0, h("59m"));
    EXPECT_EQ(1, h("3600s"));
    EXPECT_EQ(0, h("0w"));
}

TEST(Time, parse_duration_hours_rejects_garbage)
{
    EXPECT_FALSE(parse_duration_hours(""));
    EXPECT_FALSE(parse_duration_hours("h")); // no number
    EXPECT_FALSE(parse_duration_hours("7")); // no unit
    EXPECT_FALSE(parse_duration_hours("7x")); // bad unit
    EXPECT_FALSE(parse_duration_hours("abc"));
    EXPECT_FALSE(parse_duration_hours("-1h")); // negative
    EXPECT_FALSE(parse_duration_hours("7xyzh")); // trailing garbage between number and unit
}

TEST(Time, parse_validity_start_relative_uses_now_plus_offset)
{
    auto now = current_time();

    // +Nh/d/w forms are now() + N
    auto in_one_week = parse_validity_start("+1w");
    ASSERT_TRUE(in_one_week);
    auto delta_h = std::chrono::duration_cast<std::chrono::hours>(*in_one_week - now);
    // Allow a small skew because current_time() is sampled twice (here vs inside parse).
    EXPECT_NEAR(168, delta_h.count(), 1);

    auto in_24h = parse_validity_start("+24h");
    ASSERT_TRUE(in_24h);
    EXPECT_NEAR(24, std::chrono::duration_cast<std::chrono::hours>(*in_24h - now).count(), 1);

    auto in_3d = parse_validity_start("+3d");
    ASSERT_TRUE(in_3d);
    EXPECT_NEAR(72, std::chrono::duration_cast<std::chrono::hours>(*in_3d - now).count(), 1);
}

TEST(Time, parse_validity_start_absolute_iso_extended)
{
    using boost::gregorian::date;
    using boost::posix_time::ptime;
    using boost::posix_time::time_duration;

    // Date-only form pins to 00:00:00 UTC.
    auto t0 = parse_validity_start("2026-05-02");
    ASSERT_TRUE(t0);
    EXPECT_EQ(vanetza::Clock::at(ptime { date { 2026, 5, 2 } }), *t0);

    // ISO-extended form (T separator) and space form both accepted.
    auto t1 = parse_validity_start("2026-05-02T12:34:56");
    ASSERT_TRUE(t1);
    EXPECT_EQ(vanetza::Clock::at(ptime { date { 2026, 5, 2 }, time_duration { 12, 34, 56 } }), *t1);

    auto t2 = parse_validity_start("2026-05-02 12:34:56");
    ASSERT_TRUE(t2);
    EXPECT_EQ(*t1, *t2);
}

TEST(Time, parse_validity_start_rejects_garbage)
{
    EXPECT_FALSE(parse_validity_start(""));
    EXPECT_FALSE(parse_validity_start("not-a-date"));
    EXPECT_FALSE(parse_validity_start("+xyz")); // bad relative
    EXPECT_FALSE(parse_validity_start("2026-13-01")); // bad month
}