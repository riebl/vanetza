#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/burst_budget.hpp>

using Runtime = vanetza::ManualRuntime;
using namespace vanetza::dcc;

static const vanetza::Clock::duration immediately = std::chrono::milliseconds(0);

TEST(BurstBudget, normal)
{
    Runtime rt;
    BurstBudget budget(rt);

    // consume whole budget
    for (unsigned i = 0; i < 20; ++i) {
        rt.trigger(std::chrono::milliseconds(49));
        EXPECT_EQ(immediately, budget.delay());
        budget.notify();
    }

    // nothing left now
    rt.trigger(std::chrono::milliseconds(20));
    EXPECT_LT(std::chrono::seconds(9), budget.delay());
    EXPECT_GT(std::chrono::seconds(10), budget.delay());
}

TEST(BurstBudget, too_many_messages)
{
    Runtime rt;
    BurstBudget budget(rt);

    // consume whole budget immediately
    for (unsigned i = 0; i < 20; ++i) {
        EXPECT_EQ(immediately, budget.delay());
        budget.notify();
    }

    // check if budget delay recovers gradually
    EXPECT_EQ(std::chrono::seconds(10), budget.delay());
    rt.trigger(std::chrono::seconds(5));
    EXPECT_EQ(std::chrono::seconds(5), budget.delay());
    rt.trigger(std::chrono::seconds(5));
    EXPECT_EQ(immediately, budget.delay());
}

TEST(BurstBudget, too_long)
{
    Runtime rt;
    BurstBudget budget(rt);

    // start burst with one consumption
    EXPECT_EQ(immediately, budget.delay());
    budget.notify();

    // ensure we are still able to participate in burst
    rt.trigger(std::chrono::milliseconds(990));
    EXPECT_EQ(immediately, budget.delay());

    // burst is over, we will have to wait for next one
    rt.trigger(std::chrono::milliseconds(10));
    EXPECT_EQ(std::chrono::seconds(9), budget.delay());
}
