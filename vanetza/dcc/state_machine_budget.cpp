#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/state_machine.hpp>
#include <vanetza/dcc/state_machine_budget.hpp>

namespace vanetza
{
namespace dcc
{

StateMachineBudget::StateMachineBudget(const StateMachine& fsm, const Runtime& rt) :
    m_fsm(fsm), m_runtime(rt)
{
}

Clock::duration StateMachineBudget::delay()
{
    Clock::duration delay = Clock::duration::max();

    if (m_last_tx) {
        const auto last_tx = m_last_tx.get();
        const auto tx_interval = m_fsm.transmission_interval();
        if (last_tx + tx_interval < m_runtime.now()) {
            delay = Clock::duration::zero();
        } else {
            delay = last_tx + tx_interval - m_runtime.now();
        }
    } else {
        delay = Clock::duration::zero();
    }

    return delay;
}

void StateMachineBudget::notify()
{
    m_last_tx = m_runtime.now();
}

} // namespace dcc
} // namespace vanetza
