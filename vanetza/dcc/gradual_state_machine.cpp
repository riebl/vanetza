#include "gradual_state_machine.hpp"
#include <boost/format.hpp>
#include <iterator>

namespace vanetza
{
namespace dcc
{

GradualStateMachine::GradualStateMachine(const std::set<State>& states) :
    m_states(states), m_current(0)
{
    repair();
}

GradualStateMachine::GradualStateMachine(std::set<State>&& states) :
    m_states(std::move(states)), m_current(0)
{
    repair();
}

void GradualStateMachine::update(ChannelLoad cbr)
{
    static_assert(std::is_base_of<std::bidirectional_iterator_tag,
            std::iterator_traits<StateContainer::const_iterator>::iterator_category>::value,
            "State transitions require bidirectional iterators");

    auto current = std::next(m_states.begin(), m_current);
    if (cbr < current->lower_limit) {
        if (m_current > 0) {
            --m_current;
        }
    } else {
        StateContainer::const_iterator up = std::next(current);
        if (up != m_states.end() && cbr >= up->lower_limit) {
            ++m_current;
        }
    }
}

Clock::duration GradualStateMachine::transmission_interval() const
{
    return std::next(m_states.begin(), m_current)->off_time;
}

std::string GradualStateMachine::state() const
{
    if (m_current == 0) {
        return "Relaxed";
    } else if (m_current == m_states.size() - 1) {
        return "Restrictive";
    } else {
        static const boost::format fmt("Active %1%");
        return (boost::format(fmt) % m_current).str();
    }
}

void GradualStateMachine::repair()
{
    if (m_states.empty()) {
        m_states.emplace(ChannelLoad(0.0), Clock::duration::zero());
        m_current = 0;
    }
}

} // namespace dcc
} // namespace vanetza
