#include "runtime.hpp"
#include <cassert>

namespace vanetza
{

void Runtime::schedule(Clock::time_point tp, const Callback& cb)
{
    m_queue.emplace(tp, cb);
}

void Runtime::schedule(Clock::duration d, const Callback& cb)
{
    m_queue.emplace(m_now + d, cb);
}

Clock::time_point Runtime::next()
{
    Clock::time_point next_tp = Clock::time_point::max();
    if (!m_queue.empty()) {
        next_tp = std::get<0>(m_queue.top());
    }
    return next_tp;
}

const Clock::time_point& Runtime::now() const
{
    return m_now;
}

void Runtime::trigger(Clock::time_point tp)
{
    assert(tp >= m_now);
    m_now = tp;
    trigger();
}

void Runtime::trigger(Clock::duration d)
{
    m_now += d;
    trigger();
}

void Runtime::trigger()
{
    while (!m_queue.empty()) {
        if (std::get<0>(m_queue.top()) <= m_now) {
            std::get<1>(m_queue.top())(m_now);
            m_queue.pop();
        } else {
            break;
        }
    }
}

bool Runtime::sort_scheduled_callback::operator()(const ScheduledCallback& lhs, const ScheduledCallback& rhs)
{
    return std::get<0>(lhs) > std::get<0>(rhs);
}

} // namespace vanetza
