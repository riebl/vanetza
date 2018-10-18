#include <gtest/gtest.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/fully_meshed_state_machine.hpp>
#include <vanetza/dcc/state_machine_budget.hpp>

using namespace vanetza::dcc;
using vanetza::ManualRuntime;
using std::chrono::milliseconds;

static const vanetza::Clock::duration immediately = milliseconds(0);

class StateMachineBudgetTest : public ::testing::Test
{
protected:
    StateMachineBudgetTest() :
        runtime(vanetza::Clock::time_point { std::chrono::seconds(4711) }),
        budget(fsm, runtime) {}

    ManualRuntime runtime;
    FullyMeshedStateMachine fsm;
    StateMachineBudget budget;
};

TEST_F(StateMachineBudgetTest, relaxed)
{
    Relaxed relaxed;
    const auto relaxed_tx_interval = relaxed.transmission_interval();
    ASSERT_EQ(relaxed_tx_interval, fsm.transmission_interval());

    EXPECT_EQ(immediately, budget.delay());
    budget.notify();
    EXPECT_EQ(relaxed_tx_interval, budget.delay());

    runtime.trigger(relaxed_tx_interval - milliseconds(10));
    EXPECT_EQ(milliseconds(10), budget.delay());

    runtime.trigger(milliseconds(20));
    EXPECT_EQ(immediately, budget.delay());
}

TEST_F(StateMachineBudgetTest, restrictive)
{
    Restrictive restrictive;
    const auto restrictive_tx_interval = restrictive.transmission_interval();

    // put FSM into restrictive state
    for (unsigned i = 0; i < 10; ++i) {
        fsm.update(ChannelLoad(0.6));
    }
    ASSERT_STREQ("Restrictive", fsm.state().name());

    EXPECT_EQ(immediately, budget.delay());
    budget.notify();
    EXPECT_EQ(restrictive_tx_interval, budget.delay());

    runtime.trigger(restrictive_tx_interval / 2);
    EXPECT_EQ(restrictive_tx_interval / 2, budget.delay());
    runtime.trigger(restrictive_tx_interval / 2);
    EXPECT_EQ(immediately, budget.delay());
}
