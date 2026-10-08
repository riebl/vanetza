#include "gradual_state_machine.hpp"
#include <boost/format.hpp>
#include <algorithm>

namespace vanetza
{
namespace dcc
{

GradualStateMachine::GradualStateMachine(const StateContainer& states) :
    m_states(states), m_current(0)
{
    repair();
}

GradualStateMachine::GradualStateMachine(StateContainer&& states) :
    m_states(std::move(states)), m_current(0)
{
    repair();
}

void GradualStateMachine::update(ChannelLoad cbr)
{
    if (cbr < m_states[m_current].lower_limit) {
        if (m_current > 0) {
            --m_current;
        }
    } else {
        const std::size_t up = m_current + 1;
        if (up < m_states.size() && cbr >= m_states[up].lower_limit) {
            m_current = up;
        }
    }
}

Clock::duration GradualStateMachine::transmission_interval() const
{
    return m_states[m_current].off_time;
}

std::string GradualStateMachine::state() const
{
    if (m_current == 0) {
        return "Relaxed";
    } else if (m_current + 1 == m_states.size()) {
        return "Restrictive";
    } else {
        static const boost::format fmt("Active %1%");
        return (boost::format(fmt) % m_current).str();
    }
}

void GradualStateMachine::repair()
{
    std::stable_sort(m_states.begin(), m_states.end());
    auto same_limit = [](const State& a, const State& b) { return a.lower_limit == b.lower_limit; };
    m_states.erase(std::unique(m_states.begin(), m_states.end(), same_limit), m_states.end());

    if (m_states.empty()) {
        m_states.emplace_back(ChannelLoad(0.0), Clock::duration::zero());
    }
}

} // namespace dcc
} // namespace vanetza
