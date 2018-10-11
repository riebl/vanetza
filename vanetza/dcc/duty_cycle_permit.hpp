#ifndef DUTY_CYCLE_PERMIT_HPP_9QUTPOPH
#define DUTY_CYCLE_PERMIT_HPP_9QUTPOPH

#include <vanetza/common/unit_interval.hpp>

namespace vanetza
{
namespace dcc
{

/**
 * Interface for controlling channel usage by duty cycle limits
 */
class DutyCyclePermit
{
public:
    /**
     * Get allowed channel occupancy for local station in current time window
     * \return permitted duty cycle
     */
    virtual UnitInterval permitted_duty_cycle() const  = 0;

    virtual ~DutyCyclePermit() = default;
};

} // namespace dcc
} // namespace vanetza

#endif /* DUTY_CYCLE_PERMIT_HPP_9QUTPOPH */

