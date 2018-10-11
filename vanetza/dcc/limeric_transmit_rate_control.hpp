#ifndef LIMERIC_TRANSMIT_RATE_CONTROL_HPP_RY1TIBMJ
#define LIMERIC_TRANSMIT_RATE_CONTROL_HPP_RY1TIBMJ

#include <vanetza/dcc/limeric.hpp>
#include <vanetza/dcc/limeric_budget.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>

namespace vanetza
{

// forward declaration
class Runtime;

namespace dcc
{

/**
 * Transmit Rate Control implementation based on Limeric algorithm
 */
class LimericTransmitRateControl : public TransmitRateControl
{
public:
    LimericTransmitRateControl(const Runtime&, const Limeric&);

    Clock::duration delay(const Transmission&) override;
    Clock::duration interval(const Transmission&) override;
    void notify(const Transmission&) override;

    /**
     * Update TRC limits.
     * Call this method whenever Limeric updates its duty cycle.
     */
    void update();

private:
    LimericBudget m_budget;
};

} // namespace dcc
} // namespace vanetza

#endif /* LIMERIC_TRANSMIT_RATE_CONTROL_HPP_RY1TIBMJ */

