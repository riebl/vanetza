#ifndef STATE_MACHINE_HPP_0MHYOQU7
#define STATE_MACHINE_HPP_0MHYOQU7

#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/common/clock.hpp>

namespace vanetza
{
namespace dcc
{

/**
 * State machine interface used for Transmit Rate Control
 */
class StateMachine
{
public:
    /**
     * Trigger state transition by updated channel load
     * \param cl new channel load measurement
     */
    virtual void update(ChannelLoad cl) = 0;

    /**
     * Get current transmission interval
     * \return duration between two transmissions
     */
    virtual Clock::duration transmission_interval() const = 0;

    virtual ~StateMachine() = default;
};

} // namespace dcc
} // namespace vanetza

#endif /* STATE_MACHINE_HPP_0MHYOQU7 */

