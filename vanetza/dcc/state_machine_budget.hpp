#ifndef STATE_MACHINE_BUDGET_HPP_9AL8A2JG
#define STATE_MACHINE_BUDGET_HPP_9AL8A2JG

#include <vanetza/common/clock.hpp>
#include <boost/optional.hpp>

namespace vanetza
{

// forward declarations
class Runtime;
namespace dcc { class StateMachine; }

namespace dcc
{

/**
 * StateMachineBudget: TRC restrictions as determined by a state machine
 */
class StateMachineBudget
{
public:
    StateMachineBudget(const StateMachine&, const Runtime&);
    Clock::duration delay();
    void notify();

private:
    const StateMachine& m_fsm;
    const Runtime& m_runtime;
    boost::optional<Clock::time_point> m_last_tx;
};

} // namespace dcc
} // namespace vanetza

#endif /* STATE_MACHINE_BUDGET_HPP_9AL8A2JG */

