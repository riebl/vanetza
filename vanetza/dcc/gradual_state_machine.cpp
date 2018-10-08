#include "gradual_state_machine.hpp"
#include <boost/format.hpp>
#include <iterator>

namespace vanetza
{
namespace dcc
{

GradualStateMachine::GradualStateMachine(const std::set<State>& states) :
    m_states(states), m_current(m_states.begin())
{
    repair();
}

GradualStateMachine::GradualStateMachine(std::set<State>&& states) :
    m_states(std::move(states)), m_current(m_states.begin())
{
    repair();
}

void GradualStateMachine::update(ChannelLoad cbr)
{
    static_assert(std::is_base_of<std::bidirectional_iterator_tag,
            std::iterator_traits<StateContainer::const_iterator>::iterator_category>::value,
            "State transitions require bidirectional iterators");

    if (cbr < m_current->lower_limit) {
        if (m_current != m_states.begin()) {
            std::advance(m_current, -1);
        }
    } else {
        StateContainer::const_iterator up = std::next(m_current);
        if (up != m_states.end() && cbr >= up->lower_limit) {
            m_current = up;
        }
    }
}

Clock::duration GradualStateMachine::transmission_interval() const
{
    return m_current->off_time;
}

std::string GradualStateMachine::state() const
{
    if (m_current == m_states.begin()) {
        return "Relaxed";
    } else if (m_current == std::prev(m_states.end())) {
        return "Restrictive";
    } else {
        static const boost::format fmt("Active %1%");
        return (boost::format(fmt) % std::distance(m_states.begin(), m_current)).str();
    }
}

void GradualStateMachine::repair()
{
    if (m_states.empty()) {
        m_states.emplace(ChannelLoad(0.0), Clock::duration::zero());
        m_current = m_states.begin();
    }
}

} // namespace dcc
} // namespace vanetza
