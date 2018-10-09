#ifndef FULLY_MESHED_STATE_MACHINE_HPP_YPE958OH
#define FULLY_MESHED_STATE_MACHINE_HPP_YPE958OH

#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/dcc/state_machine.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace dcc
{

// constants
static constexpr Clock::duration NDL_minDccSampling = std::chrono::milliseconds(100);


class State
{
public:
    virtual Clock::duration transmission_interval() const = 0;
    virtual const char* name() const = 0;
    virtual ~State() {}
};

class Relaxed : public State
{
public:
    Clock::duration transmission_interval() const override;
    const char* name() const override;
};

class Active : public State
{
public:
    Active();
    void update(double min, double max);
    Clock::duration transmission_interval() const override;
    const char* name() const override;

private:
    static const std::size_t sc_substates;
    std::size_t m_substate;
};

class Restrictive : public State
{
public:
    Clock::duration transmission_interval() const override;
    const char* name() const override;
};

/**
 * Fully meshed TRC state machine as per TS 102 687 v1.1.1
 *
 * States are modelled according to C2C-CC DCC Whitepaper / BSP v1.2
 * State transitions are deferred internally for ramping up and cooling down over time.
 */
class FullyMeshedStateMachine : public StateMachine
{
public:
    FullyMeshedStateMachine();
    ~FullyMeshedStateMachine();

    /**
     * Notify state machine about current channel load.
     * This method expects to be called in regular intervals
     * of NDL_minDccSampling length.
     */
    void update(ChannelLoad channel_load);

    /**
     * Get currently allowed maximum message rate depending on state
     * \return messages per second
     */
    double message_rate() const;

    /**
     * Get advised transmission interval between consecutive messages
     * \return message transmission interval
     */
    Clock::duration transmission_interval() const;

    /**
     * Get state machine's active state
     */
    const State& state() const;

private:
    double max_channel_load() const;
    double min_channel_load() const;

    Relaxed m_relaxed;
    Active m_active;
    Restrictive m_restrictive;
    State* m_state;
    boost::circular_buffer<ChannelLoad> m_channel_loads;
};

} // namespace dcc
} // namespace vanetza

#endif /* FULLY_MESHED_STATE_MACHINE_HPP_YPE958OH */

