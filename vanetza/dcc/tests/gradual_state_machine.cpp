#include <gtest/gtest.h>
#include <vanetza/dcc/gradual_state_machine.hpp>
#include <chrono>

using namespace vanetza::dcc;
using namespace std::chrono;

TEST(GradualStateMachine, initial_state)
{
    GradualStateMachine fsm(etsiStates1ms);
    EXPECT_EQ("Relaxed", fsm.state());
    EXPECT_EQ(milliseconds(100), fsm.transmission_interval());
}

TEST(GradualStateMachine, transitions)
{
    GradualStateMachine fsm(etsiStates1ms);
    EXPECT_EQ("Relaxed", fsm.state());

    // now ramp up to Active 3
    fsm.update(ChannelLoad { 0.5 });
    EXPECT_EQ("Active 1", fsm.state());
    fsm.update(ChannelLoad { 0.5 });
    EXPECT_EQ("Active 2", fsm.state());
    fsm.update(ChannelLoad { 0.5 });
    EXPECT_EQ("Active 3", fsm.state());
    fsm.update(ChannelLoad { 0.5 });
    EXPECT_EQ("Active 3", fsm.state());

    // step down one
    fsm.update(ChannelLoad { 0.495 });
    EXPECT_EQ("Active 2", fsm.state());

    // go up to Restrictive gradually
    fsm.update(ChannelLoad { 0.55 });
    EXPECT_EQ("Active 3", fsm.state());
    fsm.update(ChannelLoad { 0.65 });
    EXPECT_EQ("Restrictive", fsm.state());
    EXPECT_EQ(milliseconds(1000), fsm.transmission_interval());
}

TEST(GradualStateMachine, empty_states)
{
    GradualStateMachine fsm(GradualStateMachine::StateContainer {});
    EXPECT_EQ("Relaxed", fsm.state());
    EXPECT_EQ(seconds(0), fsm.transmission_interval());
}

TEST(GradualStateMachine, one_state)
{
    GradualStateMachine fsm(GradualStateMachine::StateContainer {{ ChannelLoad(0.5), milliseconds(30) }});
    EXPECT_EQ("Relaxed", fsm.state());
    EXPECT_EQ(milliseconds(30), fsm.transmission_interval());
    fsm.update(ChannelLoad { 0.0 });
    EXPECT_EQ(milliseconds(30), fsm.transmission_interval());
    fsm.update(ChannelLoad { 1.0 });
    EXPECT_EQ(milliseconds(30), fsm.transmission_interval());
    EXPECT_EQ("Relaxed", fsm.state());
}

