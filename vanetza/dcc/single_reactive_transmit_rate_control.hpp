#ifndef SINGLE_REACTIVE_TRANSMIT_RATE_CONTROL_HPP_2GPPO79B
#define SINGLE_REACTIVE_TRANSMIT_RATE_CONTROL_HPP_2GPPO79B

#include <vanetza/dcc/state_machine_budget.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>

namespace vanetza
{

// forward declarations
class Runtime;
namespace dcc { class StateMachine; }

namespace dcc
{

/**
 * Transmit Rate Control using a single reactive state machine for all messages
 */
class SingleReactiveTransmitRateControl : public TransmitRateControl
{
public:
    SingleReactiveTransmitRateControl(const StateMachine&, const Runtime&);

    Clock::duration delay(const Transmission&) override;
    Clock::duration interval(const Transmission&) override;
    void notify(const Transmission&) override;

private:
    const StateMachine& m_fsm;
    StateMachineBudget m_fsm_budget;
};

} // namespace dcc
} // namespace vanetza

#endif /* SINGLE_REACTIVE_TRANSMIT_RATE_CONTROL_HPP_2GPPO79B */

