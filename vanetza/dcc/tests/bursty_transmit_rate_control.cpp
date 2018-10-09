#include <gtest/gtest.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/bursty_transmit_rate_control.hpp>
#include <vanetza/dcc/fully_meshed_state_machine.hpp>

using namespace std::chrono;
using namespace vanetza::dcc;
using vanetza::Clock;

static const Clock::duration immediately = milliseconds(0);

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
        EXPECT_EQ(immediately, trc.delay(Profile::DP0));
        trc.notify(Profile::DP0);
    }

    now += milliseconds(20);
    EXPECT_GT(seconds(10), trc.delay(Profile::DP0));
    EXPECT_LT(seconds(9), trc.delay(Profile::DP0));
}

TEST_F(BurstyTransmitRateControlTest, regular)
{
    const auto tx_int = milliseconds(60);
    ASSERT_EQ(tx_int, fsm.transmission_interval());

    EXPECT_EQ(immediately, trc.delay(Profile::DP1));
    trc.notify(Profile::DP1);
    EXPECT_EQ(tx_int, trc.delay(Profile::DP1));

    now += milliseconds(50);
    EXPECT_EQ(milliseconds(10), trc.delay(Profile::DP1));
    EXPECT_EQ(milliseconds(10), trc.delay(Profile::DP2));
    EXPECT_EQ(milliseconds(10), trc.delay(Profile::DP3));

    now += milliseconds(20);
    EXPECT_EQ(immediately, trc.delay(Profile::DP1));
    EXPECT_EQ(immediately, trc.delay(Profile::DP2));
    EXPECT_EQ(immediately, trc.delay(Profile::DP3));
}

TEST_F(BurstyTransmitRateControlTest, burst_regular_independence)
{
    ASSERT_EQ(immediately, trc.delay(Profile::DP1));

    // consume whole burst budget
    for (unsigned i = 0; i < 20; ++i) {
        trc.notify(Profile::DP0);
    }
    ASSERT_LT(immediately, trc.delay(Profile::DP0));

    // can send regular budget messages nonetheless
    EXPECT_EQ(immediately, trc.delay(Profile::DP3));

    // recover burst budget
    now += std::chrono::seconds(20);
    ASSERT_EQ(immediately, trc.delay(Profile::DP0));

    // use regular budget
    EXPECT_EQ(immediately, trc.delay(Profile::DP2));
    trc.notify(Profile::DP2);
    EXPECT_LT(immediately, trc.delay(Profile::DP2));

    // burst budget is not influenced
    EXPECT_EQ(immediately, trc.delay(Profile::DP0));
}

