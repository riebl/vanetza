#include <vanetza/facilities/path_history.hpp>
#include <gtest/gtest.h>

using vanetza::facilities::PathHistory;
using vanetza::facilities::PathPoint;
namespace units = vanetza::units;

#define EXPECT_PATHPOINT_EQ(a, b) \
    EXPECT_DOUBLE_EQ(a.latitude.value(), b.latitude.value()); \
    EXPECT_DOUBLE_EQ(a.longitude.value(), b.longitude.value()); \
    EXPECT_DOUBLE_EQ(a.heading.value(), b.heading.value()); \
    EXPECT_EQ(a.time, b.time)

const units::GeoAngle cOneMeterLatitude = 1.0 / 111320.0 * units::degrees;

TEST(PathHistory, reference_point) {
    PathHistory ph;
    const PathPoint default_pp;
    EXPECT_PATHPOINT_EQ(default_pp, ph.getReferencePoint());

    PathPoint first_pp;
    first_pp.longitude = 34.4 * units::degrees;
    first_pp.latitude = -10.3 * units::degrees;
    first_pp.heading = units::Angle { 48.3 * units::degrees };
    first_pp.time = boost::posix_time::time_from_string("2014-11-21 11:11:48");

    ph.addSample(first_pp);
    EXPECT_PATHPOINT_EQ(first_pp, ph.getReferencePoint());

    PathPoint second_pp;
    second_pp.longitude = 34.4 * units::degrees;
    second_pp.latitude = -10.3 * units::degrees;
    second_pp.heading = units::Angle { 48.3 * units::degrees };
    second_pp.time = boost::posix_time::time_from_string("2014-11-21 11:11:48.1");

    ph.addSample(second_pp);
    EXPECT_PATHPOINT_EQ(second_pp, ph.getReferencePoint());
}

TEST(PathHistory, concise_points_of_equal_samples) {
    PathHistory ph;
    EXPECT_EQ(0, ph.getConcisePoints().size());

    PathPoint first_pp;
    first_pp.longitude = -3.45 * units::degrees;
    first_pp.latitude = 32.98 * units::degrees;
    ph.addSample(first_pp);
    ASSERT_EQ(1, ph.getConcisePoints().size());
    EXPECT_PATHPOINT_EQ(first_pp, ph.getConcisePoints().front());

    for (unsigned i = 0; i < 10; ++i) {
        ph.addSample(first_pp);
        EXPECT_EQ(1, ph.getConcisePoints().size());
    }
}

TEST(PathHistory, concise_points_chord_length_threshold) {
    PathHistory ph;

    PathPoint pp;
    pp.longitude = 0.0 * units::degrees;
    pp.latitude = 0.0  * units::degrees;
    ph.addSample(pp);
    pp.latitude += cOneMeterLatitude;
    ph.addSample(pp);
    pp.latitude += cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(1, ph.getConcisePoints().size());

    pp.latitude += cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(1, ph.getConcisePoints().size());

    pp.latitude += 20.0 * cOneMeterLatitude;
    ph.addSample(pp);
    ASSERT_EQ(2, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(3.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());

    pp.latitude += 10.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(3, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(23.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());

    pp.latitude += 10.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(3, ph.getConcisePoints().size());

    pp.latitude += 3.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(4, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(43.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());

    pp.latitude += 23.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(5, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(46.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());
}

TEST(PathHistory, concise_points_actual_error_threshold) {
    PathHistory ph;
    PathPoint pp;
    ph.addSample(pp);

    pp.heading += units::Angle(5.0 * units::degrees);
    ph.addSample(pp);
    pp.latitude += 5.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(1, ph.getConcisePoints().size());

    pp.latitude += 10.0 * units::degrees;
    pp.longitude += 10.0 * units::degrees;
    ph.addSample(pp);
    EXPECT_EQ(2, ph.getConcisePoints().size());
}

TEST(PathHistory, concise_points_truncation) {
    PathHistory::Parameters params;
    params.retention_distance = 200.0 * units::si::meter;
    PathHistory ph(params);
    PathPoint pp;
    pp.latitude = 0.0 * units::degree;
    pp.longitude = 0.0 * units::degree;
    ph.addSample(pp);

    pp.latitude += 25.0 * cOneMeterLatitude;
    ph.addSample(pp);
    pp.latitude += 25.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(2, ph.getConcisePoints().size());

    pp.latitude += 25.0 * cOneMeterLatitude;
    ph.addSample(pp);
    EXPECT_EQ(3, ph.getConcisePoints().size());

    pp.latitude += 205.0 * cOneMeterLatitude;
    ph.addSample(pp);
    ASSERT_EQ(4, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(0.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().back().latitude.value());
    EXPECT_DOUBLE_EQ(75.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());

    ph.addSample(pp);
    ASSERT_EQ(2, ph.getConcisePoints().size());
    EXPECT_DOUBLE_EQ(75.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().back().latitude.value());
    EXPECT_DOUBLE_EQ(280.0 * cOneMeterLatitude.value(),
            ph.getConcisePoints().front().latitude.value());
}

TEST(PathHistory, clear_resets) {
    PathHistory ph;
    PathPoint pp;
    pp.latitude = 0.0 * units::degrees;
    pp.longitude = 0.0 * units::degrees;
    for (unsigned i = 0; i < 5; ++i) {
        pp.latitude += 25.0 * cOneMeterLatitude;
        ph.addSample(pp);
    }
    ASSERT_GT(ph.getConcisePoints().size(), 1u);

    ph.clear();
    EXPECT_EQ(0u, ph.getConcisePoints().size());
    EXPECT_PATHPOINT_EQ(PathPoint(), ph.getReferencePoint());

    // usable again, no stale points carried across the reset
    ph.addSample(pp);
    EXPECT_EQ(1u, ph.getConcisePoints().size());
}

TEST(PathHistory, custom_retention_keeps_more) {
    PathHistory::Parameters short_params;
    short_params.retention_distance = 200.0 * units::si::meter;
    PathHistory short_hist(short_params);

    PathHistory::Parameters long_params;
    long_params.retention_distance = 500.0 * units::si::meter;
    PathHistory long_hist(long_params);

    PathPoint pp;
    pp.latitude = 0.0 * units::degrees;
    pp.longitude = 0.0 * units::degrees;
    short_hist.addSample(pp);
    long_hist.addSample(pp);
    for (unsigned i = 0; i < 20; ++i) {
        pp.latitude += 25.0 * cOneMeterLatitude; // ~25 m steps, ~500 m total
        short_hist.addSample(pp);
        long_hist.addSample(pp);
    }
    EXPECT_GT(long_hist.getConcisePoints().size(), short_hist.getConcisePoints().size());
}

TEST(PathHistory, concise_points_retrieval_limits) {
    PathHistory ph;
    PathPoint pp;
    pp.latitude = 0.0 * units::degrees;
    pp.longitude = 0.0 * units::degrees;
    ph.addSample(pp);
    for (unsigned i = 0; i < 6; ++i) {
        pp.latitude += 25.0 * cOneMeterLatitude; // beyond chord threshold: a concise point each
        ph.addSample(pp);
    }
    const std::list<PathPoint>& full = ph.getConcisePoints();
    ASSERT_GT(full.size(), 3u);

    // concise points ~25 m apart, so at a 30 m threshold:
    // "covering" includes the point crossing 30 m, "within" excludes it
    const auto covering = ph.getConcisePointsMinLength(30.0 * units::si::meter);
    const auto within = ph.getConcisePointsMaxLength(30.0 * units::si::meter);
    EXPECT_EQ(3, std::distance(covering.begin(), covering.end()));
    EXPECT_EQ(2, std::distance(within.begin(), within.end()));
    EXPECT_DOUBLE_EQ(full.front().latitude.value(), covering.front().latitude.value());
    EXPECT_DOUBLE_EQ(full.front().latitude.value(), within.front().latitude.value());

    // optional point limit keeps the newest points
    const auto capped = ph.getConcisePointsMinLength(10000.0 * units::si::meter, 2);
    EXPECT_EQ(2, std::distance(capped.begin(), capped.end()));
    EXPECT_DOUBLE_EQ(full.front().latitude.value(), capped.front().latitude.value());
}

// Three samples over a 5 m chord: estimated error is 2.5 m * tan(delta_phi / 4),
// exceeding the allowable 0.47 m once heading changes by more than about 42.6 degrees.
// Only first and last heading matter, thus samples can simply keep going straight.
static bool turn_adds_concise_point(double start_heading, double end_heading)
{
    PathHistory ph;
    PathPoint pp;
    pp.heading = units::Angle(start_heading * units::degrees);
    ph.addSample(pp);
    pp.latitude += 2.5 * cOneMeterLatitude;
    ph.addSample(pp);
    pp.latitude += 2.5 * cOneMeterLatitude;
    pp.heading = units::Angle(end_heading * units::degrees);
    ph.addSample(pp);
    return ph.getConcisePoints().size() > 1;
}

TEST(PathHistory, concise_points_right_turn) {
    EXPECT_FALSE(turn_adds_concise_point(0.0, 40.0));
    EXPECT_TRUE(turn_adds_concise_point(0.0, 45.0));
}

TEST(PathHistory, concise_points_left_turn) {
    EXPECT_FALSE(turn_adds_concise_point(0.0, -40.0));
    EXPECT_TRUE(turn_adds_concise_point(0.0, -45.0));
    EXPECT_TRUE(turn_adds_concise_point(90.0, 45.0));
}

TEST(PathHistory, concise_points_north_crossing) {
    // 45 degrees across north, not 315 degrees
    EXPECT_TRUE(turn_adds_concise_point(340.0, 25.0));
    EXPECT_TRUE(turn_adds_concise_point(25.0, 340.0));
    // 0.4 degrees across north, not 359.6 degrees
    EXPECT_FALSE(turn_adds_concise_point(0.2, 359.8));
    EXPECT_FALSE(turn_adds_concise_point(359.8, 0.2));
}

TEST(PathHistory, concise_points_gradual_turn) {
    // heading change counts from last concise point, not from previous sample
    PathHistory ph;
    PathPoint pp;
    ph.addSample(pp);
    pp.latitude += 2.5 * cOneMeterLatitude;
    pp.heading = units::Angle(22.5 * units::degrees);
    ph.addSample(pp);
    pp.latitude += 2.5 * cOneMeterLatitude;
    pp.heading = units::Angle(45.0 * units::degrees);
    ph.addSample(pp);
    EXPECT_EQ(2u, ph.getConcisePoints().size());
}
