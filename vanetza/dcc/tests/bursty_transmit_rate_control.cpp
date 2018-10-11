#include <gtest/gtest.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/bursty_transmit_rate_control.hpp>
#include <vanetza/dcc/fully_meshed_state_machine.hpp>

using namespace std::chrono;
using namespace vanetza::dcc;
using vanetza::Clock;

static const Clock::duration immediately = milliseconds(0);
static const TransmissionLite dp0 { Profile::DP0, 0 };
static const TransmissionLite dp1 { Profile::DP1, 0 };
static const TransmissionLite dp2 { Profile::DP2, 0 };
static const TransmissionLite dp3 { Profile::DP3, 0 };

class BurstyTransmitRateControlTest : public ::testing::Test
{
protected:
    BurstyTransmitRateControlTest() : now(seconds(4711)), trc(fsm, now) {}

    Clock::time_point now;
    FullyMeshedStateMachine fsm;
    BurstyTransmitRateControl trc;
};

TEST_F(BurstyTransmitRateControlTest, burst)
{
    for (unsigned i = 0; i < 20; ++i) {
        now += milliseconds(49);
        EXPECT_EQ(immediately, trc.delay(dp0));
        trc.notify(dp0);
    }

    now += milliseconds(20);
    EXPECT_GT(seconds(10), trc.delay(dp0));
    EXPECT_LT(seconds(9), trc.delay(dp0));
}

TEST_F(BurstyTransmitRateControlTest, regular)
{
    const auto tx_int = milliseconds(60);
    ASSERT_EQ(tx_int, fsm.transmission_interval());

    EXPECT_EQ(immediately, trc.delay(dp1));
    trc.notify(dp1);
    EXPECT_EQ(tx_int, trc.delay(dp1));

    now += milliseconds(50);
    EXPECT_EQ(milliseconds(10), trc.delay(dp1));
    EXPECT_EQ(milliseconds(10), trc.delay(dp2));
    EXPECT_EQ(milliseconds(10), trc.delay(dp3));

    now += milliseconds(20);
    EXPECT_EQ(immediately, trc.delay(dp1));
    EXPECT_EQ(immediately, trc.delay(dp2));
    EXPECT_EQ(immediately, trc.delay(dp3));
}

TEST_F(BurstyTransmitRateControlTest, burst_regular_independence)
{
    ASSERT_EQ(immediately, trc.delay(dp1));

    // consume whole burst budget
    for (unsigned i = 0; i < 20; ++i) {
        trc.notify(dp0);
    }
    ASSERT_LT(immediately, trc.delay(dp0));

    // can send regular budget messages nonetheless
    EXPECT_EQ(immediately, trc.delay(dp3));

    // recover burst budget
    now += std::chrono::seconds(20);
    ASSERT_EQ(immediately, trc.delay(dp0));

    // use regular budget
    EXPECT_EQ(immediately, trc.delay(dp2));
    trc.notify(dp2);
    EXPECT_LT(immediately, trc.delay(dp2));

    // burst budget is not influenced
    EXPECT_EQ(immediately, trc.delay(dp0));
}

