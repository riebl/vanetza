#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/position_updater.hpp>
#include <vanetza/geonet/router.hpp>
#include <chrono>

using namespace vanetza;
using namespace vanetza::geonet;
using namespace std::chrono;

class IncrementalPositionProvider : public PositionProvider
{
public:
    const PositionFix& position_fix() override
    {
        next_position();
        return position;
    }

private:
    void next_position()
    {
        ++updates;
        position.latitude = updates * 3.0 * units::degree;
        position.longitude = updates * -1.5 * units::degree;
        position.confidence.semi_minor = 25.0 * units::si::meter;
        position.confidence.semi_major = 25.0 * units::si::meter;
    }

    unsigned updates = 0;
    PositionFix position;
};

class PositionUpdaterTest : public ::testing::Test
{
public:
    PositionUpdaterTest() :
        router(runtime, mib), updater(runtime, positioning, router)
    {
    }

    void SetUp() override
    {
        mib.itsGnSecurity = false; /*< no security entity required */
        mib.itsGnMinimumUpdateFrequencyEPV = 1.0 * units::si::hertz;
    }

    unsigned lpv_updates()
    {
        units::GeoAngle latitude { router.get_local_position_vector().latitude };
        return latitude.value() / 3;
    }

protected:
    ManualRuntime runtime;
    MIB mib;
    Router router;
    IncrementalPositionProvider positioning;
    PositionUpdater updater;
};

TEST_F(PositionUpdaterTest, default_update_rate)
{
    EXPECT_EQ(0, lpv_updates());
    runtime.trigger(milliseconds(950));
    EXPECT_EQ(0, lpv_updates());
    runtime.trigger(milliseconds(60));
    EXPECT_EQ(1, lpv_updates());
    runtime.trigger(seconds(1));
    EXPECT_EQ(2, lpv_updates());
    runtime.trigger(seconds(1));
    EXPECT_EQ(3, lpv_updates());
}

TEST_F(PositionUpdaterTest, custom_update_interval)
{
    updater.update_rate(seconds(10));
    runtime.trigger(seconds(9));
    EXPECT_EQ(0, lpv_updates());
    runtime.trigger(seconds(1));
    EXPECT_EQ(1, lpv_updates());
    runtime.trigger(seconds(10));
    EXPECT_EQ(2, lpv_updates());
}

TEST_F(PositionUpdaterTest, custom_update_frequency)
{
    updater.update_rate(4.0 * units::si::hertz);
    runtime.trigger(milliseconds(250));
    EXPECT_EQ(1, lpv_updates());
    runtime.trigger(milliseconds(250));
    EXPECT_EQ(2, lpv_updates());
}

TEST_F(PositionUpdaterTest, zero_hertz)
{
    updater.update_rate(0.0 * units::si::hertz);
    runtime.trigger(seconds(60));
    EXPECT_EQ(0, lpv_updates());
}

TEST_F(PositionUpdaterTest, negative_interval)
{
    updater.update_rate(milliseconds(-200));
    runtime.trigger(seconds(60));
    EXPECT_EQ(0, lpv_updates());
}
