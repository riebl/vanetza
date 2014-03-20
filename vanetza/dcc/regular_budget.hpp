#ifndef REGULAR_BUDGET_HPP_9AL8A2JG
#define REGULAR_BUDGET_HPP_9AL8A2JG

#include <vanetza/common/clock.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace dcc
{

// forward declarations
class StateMachine;

class RegularBudget
{
public:
    RegularBudget(const StateMachine&, const clock::time_point&);
    clock::duration delay();
    void notify();

private:
    const StateMachine& m_fsm;
    const clock::time_point& m_clock;
    boost::optional<clock::time_point> m_last_tx;
};

} // namespace dcc
} // namespace vanetza

#endif /* REGULAR_BUDGET_HPP_9AL8A2JG */

