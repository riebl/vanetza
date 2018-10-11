#ifndef LIMERIC_BUDGET_HPP_RQYL16AG
#define LIMERIC_BUDGET_HPP_RQYL16AG

#include <vanetza/common/clock.hpp>

namespace vanetza
{

// forward declaration
class Runtime;

namespace dcc
{

// forward declaration
class DutyCyclePermit;

/**
 * LimericBudget models Annex B of TS 102 687 v1.2.1, i.e.
 * packet handling to meet the channel occupancy limit
 */
class LimericBudget
{
public:
    LimericBudget(const DutyCyclePermit&, const Runtime&);

    /**
     * Get delay until next transmission is allowed
     * \return remaining transmission delay
     */
    Clock::duration delay();

    /**
     * Get current interval between transmissions
     * \return transmission interval
     */
    Clock::duration interval();

    /**
     * Notify budget about transmission activity
     * \param tx_on over-the-air duration of transmission
     */
    void notify(Clock::duration tx_on);

    /**
     * Recalculate current transmission interval.
     *
     * Transmission interval is derived from Limeric's current permitted duty cycle.
     * Hence, this method should be called whenever Limeric changes its duty cycle.
     */
    void update();

private:
    Clock::duration clamp_interval(Clock::duration) const;

    const DutyCyclePermit& m_duty_cycle_permit;
    const Runtime& m_runtime;
    Clock::duration m_interval;
    Clock::time_point m_tx_start;
    Clock::duration m_tx_on;
};

} // namespace dcc
} // namespace vanetza

#endif /* LIMERIC_BUDGET_HPP_RQYL16AG */

