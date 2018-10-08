#ifndef GRADUAL_STATE_MACHINE_HPP_CGPVG4CS
#define GRADUAL_STATE_MACHINE_HPP_CGPVG4CS

#include <vanetza/common/clock.hpp>
#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/dcc/state_machine.hpp>
#include <set>
#include <string>

namespace vanetza
{
namespace dcc
{

/**
 * Reactive Transmit Rate Control (TRC) based on a state machine.
 *
 * This implementation complies with ETSI TS 102 687 v1.2.1,
 * i.e. transitions can only happen gradually between neighbouring states.
 * No ramping up or cooling down timing behaviour exists (not specified anymore).
 */
class GradualStateMachine : public StateMachine
{
public:
    struct State
    {
        constexpr State(ChannelLoad limit, Clock::duration off_time) :
            lower_limit(limit), off_time(off_time) {}

        ChannelLoad lower_limit;
        Clock::duration off_time;

        bool operator<(const State& other) const { return lower_limit < other.lower_limit; }
    };
    using StateContainer = std::set<State>;

    GradualStateMachine(const StateContainer&);
    GradualStateMachine(StateContainer&&);

    void update(ChannelLoad) override;
    Clock::duration transmission_interval() const override;
    std::string state() const;

private:
    void repair();

    StateContainer m_states;
    StateContainer::const_iterator m_current;
};

/**
 * CBR mapping as per TS 102 687 V1.2.1 Table A.1 (max T_on = 1ms)
 */
static const GradualStateMachine::StateContainer etsiStates1ms = {
    { ChannelLoad(0.00), std::chrono::milliseconds(100) },
    { ChannelLoad(0.30), std::chrono::milliseconds(200) },
    { ChannelLoad(0.40), std::chrono::milliseconds(400) },
    { ChannelLoad(0.50), std::chrono::milliseconds(500) },
    { ChannelLoad(0.60), std::chrono::milliseconds(1000) }
};

/**
 * CBR mapping as per TS 102 686 V1.2.1 Table A.2 (max T_on = 500 us)
 */
static const GradualStateMachine::StateContainer etsiStates500us = {
    { ChannelLoad(0.00), std::chrono::milliseconds(50) },
    { ChannelLoad(0.30), std::chrono::milliseconds(100) },
    { ChannelLoad(0.40), std::chrono::milliseconds(200) },
    { ChannelLoad(0.50), std::chrono::milliseconds(250) },
    { ChannelLoad(0.65), std::chrono::milliseconds(1000) }
};

} // namespace dcc
} // namespace vanetza

#endif /* GRADUAL_STATE_MACHINE_HPP_CGPVG4CS */

