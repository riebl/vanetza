#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/dcc/duty_cycle_permit.hpp>
#include <vanetza/dcc/limeric_budget.hpp>
#include <chrono>

using namespace vanetza;
using namespace vanetza::dcc;
using std::chrono::milliseconds;
using std::chrono::microseconds;

namespace std { namespace chrono {

template<typename Rep, typename Period>
void PrintTo(const duration<Rep, Period> d, std::ostream* os)
{
    duration<double, std::milli> ms = d;
    *os << ms.count() << " ms";
}

}}

class LimericBudgetTest : public ::testing::Test
{
public:
    LimericBudgetTest() : budget(dcp, runtime) {}

    class MockDutyCyclePermit : public vanetza::dcc::DutyCyclePermit
    {
    public:
        MockDutyCyclePermit() : m_duty_cycle(0.02) {}

        UnitInterval permitted_duty_cycle() const { return m_duty_cycle; }
        void permitted_duty_cycle(double dc) { m_duty_cycle = UnitInterval { dc }; }

    private:
        UnitInterval m_duty_cycle;
    };

    ManualRuntime runtime;
    MockDutyCyclePermit dcp;
    LimericBudget budget;
};

TEST_F(LimericBudgetTest, init)
{
    EXPECT_EQ(milliseconds(25), budget.interval());
    EXPECT_EQ(milliseconds(0), budget.delay());
}

TEST_F(LimericBudgetTest, notify)
{
    budget.notify(milliseconds(2));
    EXPECT_EQ(milliseconds(100), budget.interval());
    EXPECT_EQ(budget.interval(), budget.delay());

    runtime.trigger(milliseconds(60));
    EXPECT_EQ(milliseconds(100), budget.interval());
    EXPECT_EQ(milliseconds(40), budget.delay());

    runtime.trigger(milliseconds(60));
    EXPECT_EQ(milliseconds(0), budget.delay());

    budget.notify(microseconds(100));
    EXPECT_EQ(milliseconds(25), budget.interval()); // lower limit

    budget.notify(milliseconds(30));
    EXPECT_EQ(milliseconds(1000), budget.interval()); // upper limit
}

TEST_F(LimericBudgetTest, update)
{
    budget.update(); // usually this should be called by Limeric's hook directly
    EXPECT_EQ(milliseconds(25), budget.interval()); // no previous transmission duration known yet

    budget.notify(milliseconds(1));
    EXPECT_EQ(milliseconds(50), budget.interval());

    runtime.trigger(milliseconds(10));
    EXPECT_EQ(milliseconds(40), budget.delay());

    dcp.permitted_duty_cycle(0.01); // half of previous duty cycle
    budget.update();
    EXPECT_EQ(milliseconds(90), budget.interval());
    EXPECT_EQ(milliseconds(80), budget.delay());

    runtime.trigger(milliseconds(62));
    dcp.permitted_duty_cycle(0.04);
    budget.update();
    EXPECT_EQ(milliseconds(77), budget.interval());
    EXPECT_EQ(milliseconds(5), budget.delay());
}
