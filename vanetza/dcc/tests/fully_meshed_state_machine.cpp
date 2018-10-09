#include <gtest/gtest.h>
#include <vanetza/dcc/fully_meshed_state_machine.hpp>

using std::chrono::milliseconds;
using namespace vanetza::dcc;


TEST(FullyMeshedStateMachine, ctor)
{
    FullyMeshedStateMachine sm;
    EXPECT_STREQ("Relaxed", sm.state().name());
    EXPECT_EQ(milliseconds(60), sm.transmission_interval());
    EXPECT_NEAR(16.66, sm.message_rate(), 0.01);
}

TEST(FullyMeshedStateMachine, ramp_up)
{
    FullyMeshedStateMachine sm;

    // keep below minChannelLoad at first: relaxed
    sm.update(ChannelLoad(0.16));
    EXPECT_STREQ("Relaxed", sm.state().name());

    // now exceed minChannelLoad for 10 samples: active 1
    for (unsigned i = 0; i < 9; ++i) {
        sm.update(ChannelLoad(0.2));
        EXPECT_STREQ("Relaxed", sm.state().name());
    }
    sm.update(ChannelLoad(0.2));
    EXPECT_STREQ("Active 1", sm.state().name());

    // now let's jump to active 3 directly
    sm.update(ChannelLoad(0.4));
    EXPECT_STREQ("Active 3", sm.state().name());

    // jump to active 5
    sm.update(ChannelLoad(0.55));
    EXPECT_STREQ("Active 5", sm.state().name());

    // ramp up to restrictive
    for (unsigned i = 0; i < 9; ++i) {
        sm.update(ChannelLoad(0.6));
        EXPECT_STREQ("Active 5", sm.state().name());
    }
    sm.update(ChannelLoad(0.6));
    EXPECT_STREQ("Restrictive", sm.state().name());
}

TEST(FullyMeshedStateMachine, ramp_down)
{
    FullyMeshedStateMachine sm;

    // fill up CL ring buffer for restrictive
    for (unsigned i = 0; i < 10; ++i) {
        sm.update(ChannelLoad(0.7));
    }
    ASSERT_STREQ("Restrictive", sm.state().name());

    // insert 55 % CL for active 5 state (later on)
    sm.update(ChannelLoad(0.55));
    // cool down 48 of 50 samples to CL = 50% (active 4)
    for (unsigned i = 0; i < 48; ++i) {
        sm.update(ChannelLoad(0.5));
    }
    EXPECT_STREQ("Restrictive", sm.state().name());

    // -> active 5 (one last 55 % CL sample)
    sm.update(ChannelLoad(0.5));
    EXPECT_STREQ("Active 5", sm.state().name());

    // -> active 4
    sm.update(ChannelLoad(0.5));
    EXPECT_STREQ("Active 4", sm.state().name());
}

TEST(State, relaxed)
{
    Relaxed relaxed;
    EXPECT_STREQ("Relaxed", relaxed.name());
    EXPECT_EQ(milliseconds(60), relaxed.transmission_interval());
}

TEST(State, active)
{
    Active active;
    EXPECT_STREQ("Active 1", active.name());
    EXPECT_EQ(milliseconds(100), active.transmission_interval());

    active.update(0.20, 0.36);
    EXPECT_STREQ("Active 3", active.name());
    EXPECT_EQ(milliseconds(260), active.transmission_interval());

    active.update(0.51, 0.52);
    EXPECT_STREQ("Active 5", active.name());
    EXPECT_EQ(milliseconds(420), active.transmission_interval());

    active.update(0.30, 0.44);
    EXPECT_STREQ("Active 4", active.name());
    EXPECT_EQ(milliseconds(340), active.transmission_interval());

    active.update(0.20, 0.30);
    EXPECT_STREQ("Active 2", active.name());
    EXPECT_EQ(milliseconds(180), active.transmission_interval());
}

TEST(State, restrictive)
{
    Restrictive restrictive;
    EXPECT_STREQ("Restrictive", restrictive.name());
    EXPECT_EQ(milliseconds(460), restrictive.transmission_interval());
}

