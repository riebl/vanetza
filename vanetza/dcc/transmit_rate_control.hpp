#ifndef TRANSMIT_RATE_CONTROL_HPP_NOPDFSY6
#define TRANSMIT_RATE_CONTROL_HPP_NOPDFSY6

#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/profile.hpp>

namespace vanetza
{
namespace dcc
{

class TransmitRateThrottle
{
public:
    /**
     * Duration until next transmission has to be delayed
     * \param p Profile associated to transmission
     * \return waiting time until next transmission is allowed
     */
    virtual Clock::duration delay(Profile) = 0;

    /**
     * Current interval between packets
     * \param p Profile
     * \return interval enforced by DCC_access
     */
    virtual Clock::duration interval(Profile) = 0;

    virtual ~TransmitRateThrottle() = default;
};

class TransmitRateFeedback
{
public:
    /**
     * Notify about an actual transmission at link layer
     * \param p Profile associated with transmission
     */
    virtual void notify(Profile) = 0;

    virtual ~TransmitRateFeedback() = default;
};

class TransmitRateControl : public TransmitRateThrottle, public TransmitRateFeedback
{
};

} // namespace dcc
} // namespace vanetza

#endif /* TRANSMIT_RATE_CONTROL_HPP_NOPDFSY6 */

