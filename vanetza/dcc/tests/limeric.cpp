#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/limeric.hpp>

using namespace vanetza;
using namespace vanetza::dcc;
using std::chrono::milliseconds;

namespace vanetza {
    void PrintTo(const UnitInterval& cl, std::ostream* os) { *os << cl.value(); }
}

class LimericTest : public ::testing::Test
{
public:
    LimericTest() : runtime(Clock::time_point { milliseconds(567) }), limeric(runtime) {}

    ManualRuntime runtime;
    Limeric limeric;
};

TEST_F(LimericTest, init)
{
    EXPECT_EQ(ChannelLoad { 0.0 }, limeric.average_cbr());
    EXPECT_EQ(UnitInterval { 0.0153 }, limeric.permitted_duty_cycle());
}

TEST_F(LimericTest, average_cbr_only_measured)
{
    limeric.update_cbr(ChannelLoad { 0.2 });
    EXPECT_EQ(ChannelLoad { 0.2 }, limeric.average_cbr());

    limeric.update_cbr(ChannelLoad { 0.4 });
    EXPECT_EQ(ChannelLoad { 0.3 }, limeric.average_cbr());

    // now internal buffer filled up, 0.3 is assumed to be "previous" average
    limeric.update_cbr(ChannelLoad { 0.6 });
    EXPECT_EQ(ChannelLoad { 0.4 }, limeric.average_cbr());

    // previous average changes only at update cycle if buffer is full
    limeric.update_cbr(ChannelLoad { 0.6 });
    EXPECT_EQ(ChannelLoad { 0.45 }, limeric.average_cbr());
}

TEST_F(LimericTest, average_cbr_with_cycle)
{
    limeric.update_cbr(ChannelLoad { 0.3 });
    limeric.update_cbr(ChannelLoad { 0.4 });
    EXPECT_EQ(ChannelLoad { 0.35 }, limeric.average_cbr());

    runtime.trigger(milliseconds(200));
    // internal average is set to 0.35 now
    EXPECT_EQ(ChannelLoad { 0.35 }, limeric.average_cbr());

    limeric.update_cbr(ChannelLoad { 0.2 });
    EXPECT_EQ(ChannelLoad { 0.325}, limeric.average_cbr());

    limeric.update_cbr(ChannelLoad { 0.1 });
    EXPECT_EQ(ChannelLoad { 0.25 }, limeric.average_cbr());

    limeric.update_cbr(ChannelLoad { 0.1 });
    EXPECT_EQ(ChannelLoad { 0.225 }, limeric.average_cbr());

    runtime.trigger(milliseconds(200));
    // internal average is set to 0.225 now
    EXPECT_EQ(ChannelLoad { 0.1625 }, limeric.average_cbr());

    limeric.update_cbr(ChannelLoad { 0.3 });
    limeric.update_cbr(ChannelLoad { 0.5 });
    EXPECT_EQ(ChannelLoad { 0.3125 }, limeric.average_cbr());
}

TEST_F(LimericTest, scheduling)
{
    unsigned invocation_count = 0;
    limeric.on_duty_cycle_change = [&](const Limeric* limeric_on_change, Clock::time_point tp) {
        EXPECT_EQ(&limeric, limeric_on_change);
        // expectation: on_duty_cycle_change invocactions exactly at 200ms boundaries
        EXPECT_EQ(milliseconds(0), tp.time_since_epoch() % milliseconds(200));
        ++invocation_count;
    };

    // start at 567 ms, expected first invocation at 800 ms
    runtime.trigger(milliseconds(200)); // 767 ms
    EXPECT_EQ(0, invocation_count);
    runtime.trigger(milliseconds(50)); // 817 ms
    EXPECT_EQ(1, invocation_count);
    runtime.trigger(milliseconds(100)); // 917 ms
    EXPECT_EQ(1, invocation_count);
    runtime.trigger(milliseconds(50)); // 967 ms
    EXPECT_EQ(1, invocation_count);
    runtime.trigger(milliseconds(33)); // 1000 ms
    EXPECT_EQ(2, invocation_count);
}

TEST_F(LimericTest, dual_alpha)
{
    Limeric::DualAlphaParameters dual_params;
    Limeric limeric_dual(runtime);
    limeric_dual.configure_dual_alpha(dual_params);

    auto update_cbr = [&](double cbr) {
        limeric.update_cbr(ChannelLoad { cbr });
        limeric_dual.update_cbr(ChannelLoad { cbr });
    };

    // set average CBR to 0.8
    update_cbr(0.8);
    update_cbr(0.8);

    EXPECT_EQ(limeric.permitted_duty_cycle(), limeric_dual.permitted_duty_cycle());
    runtime.trigger(milliseconds(200));
    EXPECT_EQ(limeric.permitted_duty_cycle(), limeric_dual.permitted_duty_cycle());

    // Limeric with dual-alpha is expected to converge earlier towards target CBR
    for (int i = 0; i < 30; ++i) {
        runtime.trigger(milliseconds(200));
    }
    EXPECT_GT(limeric.permitted_duty_cycle(), limeric_dual.permitted_duty_cycle());
}
