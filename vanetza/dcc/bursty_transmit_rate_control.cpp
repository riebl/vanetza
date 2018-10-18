#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/bursty_transmit_rate_control.hpp>
#include <vanetza/dcc/state_machine.hpp>
#include <stdexcept>

namespace vanetza
{
namespace dcc
{

BurstyTransmitRateControl::BurstyTransmitRateControl(const StateMachine& fsm, const Runtime& rt) :
    m_burst_budget(rt), m_fsm_budget(fsm, rt), m_fsm(fsm)
{
}

Clock::duration BurstyTransmitRateControl::delay(const Transmission& tx)
{
    Clock::duration delay = Clock::duration::max();

    switch (tx.profile()) {
        case Profile::DP0:
            delay = m_burst_budget.delay();
            break;
        case Profile::DP1:
        case Profile::DP2:
        case Profile::DP3:
            delay = m_fsm_budget.delay();
            break;
        default:
            throw std::invalid_argument("Invalid DCC Profile");
            break;
    };

    return delay;
}

Clock::duration BurstyTransmitRateControl::interval(const Transmission& tx)
{
    Clock::duration interval = Clock::duration::max();

    switch (tx.profile()) {
        case Profile::DP0:
            interval = m_burst_budget.burst_period();
            break;
        case Profile::DP1:
        case Profile::DP2:
        case Profile::DP3:
            interval = m_fsm.transmission_interval();
            break;
        default:
            throw std::invalid_argument("Invalid DCC Profile");
            break;
    }

    return interval;
}

void BurstyTransmitRateControl::notify(const Transmission& tx)
{
    switch (tx.profile()) {
        case Profile::DP0:
            m_burst_budget.notify();
            break;
        case Profile::DP1:
        case Profile::DP2:
        case Profile::DP3:
            m_fsm_budget.notify();
            break;
        default:
            throw std::invalid_argument("Invalid DCC Profile");
            break;
    };
}

} // namespace dcc
} // namespace vanetza
