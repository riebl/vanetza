#include <gtest/gtest.h>
#include <vanetza/geodesy/geodesy.hpp>
#include <vanetza/geodesy/haversine.hpp>
#ifdef VANETZA_WITH_GEOGRAPHICLIB
#include <vanetza/geodesy/geographiclib.hpp>
#endif

using namespace vanetza::geodesy;
namespace units = vanetza::units;
using units::si::meter;
using units::degree;

// Technische Hochschule Ingolstadt
static const GeodeticPosition thi(48.76714 * degree, 11.43263 * degree);
// Zentrum fuer Angewandte Forschung
static const GeodeticPosition zaf(48.7656 * degree, 11.4296 * degree);
// Munich (short range ~70 km)
static const GeodeticPosition munich(48.1351 * degree, 11.5820 * degree);
// Frankfurt (medium range ~304 km)
static const GeodeticPosition frankfurt(50.1109 * degree, 8.6821 * degree);
// Sao Paulo (long range ~10000 km)
static const GeodeticPosition sao_paulo(-25.41272 * degree, -49.24815 * degree);


TEST(GeodesyHaversine, distance_zero)
{
    auto d = haversine::distance(thi, thi);
    EXPECT_DOUBLE_EQ(0.0, d / meter);
}

TEST(GeodesyHaversine, distance_short_range)
{
    auto d = haversine::distance(thi, zaf);
    EXPECT_NEAR(d / meter, 280.0, 10.0);
}

TEST(GeodesyHaversine, distance_medium_range)
{
    auto d = haversine::distance(frankfurt, munich);
    EXPECT_NEAR(d / meter, 304000.0, 3000.0);
}

TEST(GeodesyHaversine, local_cartesian_short_range)
{
    auto cart = haversine::local_cartesian(thi, zaf);
    // ZAF is roughly south-west of THI
    EXPECT_NEAR(cart.x / meter, -222.0, 5.0);
    EXPECT_NEAR(cart.y / meter, -171.0, 5.0);
}

TEST(GeodesyHaversine, local_cartesian_zero)
{
    auto cart = haversine::local_cartesian(thi, thi);
    EXPECT_DOUBLE_EQ(cart.x / meter, 0.0);
    EXPECT_DOUBLE_EQ(cart.y / meter, 0.0);
}

#ifdef VANETZA_WITH_GEOGRAPHICLIB

TEST(GeodesyGeographicLib, distance_matches_known_value)
{
    auto d = geographiclib::distance(thi, sao_paulo);
    EXPECT_NEAR(d / meter, 10185367.442, 0.5);
}

TEST(GeodesyGeographicLib, local_cartesian_known_value)
{
    auto cart = geographiclib::local_cartesian(thi, zaf);
    EXPECT_NEAR(cart.x / meter, -222.74, 0.01);
    EXPECT_NEAR(cart.y / meter, -171.25, 0.01);
}

TEST(GeodesyComparison, distance_short_range)
{
    auto h = haversine::distance(thi, zaf);
    auto g = geographiclib::distance(thi, zaf);
    EXPECT_NEAR(h / meter, g / meter, std::abs(g / meter * 0.005)); // <0.5%
}

TEST(GeodesyComparison, distance_medium_range)
{
    auto h = haversine::distance(frankfurt, munich);
    auto g = geographiclib::distance(frankfurt, munich);
    EXPECT_NEAR(h / meter, g / meter, std::abs(g / meter * 0.005)); // <0.5%
}

TEST(GeodesyComparison, distance_long_range)
{
    auto h = haversine::distance(thi, sao_paulo);
    auto g = geographiclib::distance(thi, sao_paulo);
    EXPECT_NEAR(h / meter, g / meter, std::abs(g / meter * 0.005)); // <0.5%
}

TEST(GeodesyComparison, local_cartesian_short_range)
{
    auto h = haversine::local_cartesian(thi, zaf);
    auto g = geographiclib::local_cartesian(thi, zaf);
    EXPECT_NEAR(h.x / meter, g.x / meter, 1.0); // <1m
    EXPECT_NEAR(h.y / meter, g.y / meter, 1.0);
}

TEST(GeodesyComparison, local_cartesian_medium_range)
{
    auto h = haversine::local_cartesian(thi, munich);
    auto g = geographiclib::local_cartesian(thi, munich);
    EXPECT_NEAR(h.x / meter, g.x / meter, std::abs(g.x / meter * 0.02)); // <2%
    EXPECT_NEAR(h.y / meter, g.y / meter, std::abs(g.y / meter * 0.02));
}

#endif // VANETZA_WITH_GEOGRAPHICLIB
