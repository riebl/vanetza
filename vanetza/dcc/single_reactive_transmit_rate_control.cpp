#include "single_reactive_transmit_rate_control.hpp"
#include "state_machine.hpp"

namespace vanetza
{
namespace dcc
{

SingleReactiveTransmitRateControl::SingleReactiveTransmitRateControl(const StateMachine& fsm, const Clock::time_point& clock) :
    m_fsm(fsm), m_fsm_budget(fsm, clock)
{
}

Clock::duration SingleReactiveTransmitRateControl::interval(const Transmission&)
{
    return m_fsm.transmission_interval();
}

Clock::duration SingleReactiveTransmitRateControl::delay(const Transmission&)
{
    return m_fsm_budget.delay();
}

void SingleReactiveTransmitRateControl::notify(const Transmission&)
{
    m_fsm_budget.notify();
}

} // namespace dcc
} // namespace vanetza
