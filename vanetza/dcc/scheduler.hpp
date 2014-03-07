#ifndef SCHEDULER_HPP_AM7LROYD
#define SCHEDULER_HPP_AM7LROYD

#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/burst_budget.hpp>
#include <vanetza/dcc/regular_budget.hpp>
#include <vanetza/dcc/profile.hpp>

namespace vanetza
{
namespace dcc
{

class Scheduler
{
public:
    Scheduler(const StateMachine&, const clock::time_point& clock);

    clock::duration delay(Profile);
    void notify(Profile);

private:
    const StateMachine& m_fsm;
    const clock::time_point& m_clock;
    BurstBudget m_burst_budget;
    RegularBudget m_regular_budget;
};

} // namespace dcc
} // namespace vanetza

#endif /* SCHEDULER_HPP_AM7LROYD */

