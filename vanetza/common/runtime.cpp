#include "runtime.hpp"
#include <cassert>

namespace vanetza
{

Runtime::Runtime(Clock::time_point init) : m_now(init)
{
}

void Runtime::schedule(Clock::time_point tp, const Callback& cb, const std::string& name)
{
    m_queue.emplace(queue_type::value_type { tp, cb, name });
}

void Runtime::schedule(Clock::duration d, const Callback& cb, const std::string& name)
{
    schedule(m_now + d, cb, name);
}

void Runtime::schedule(Clock::time_point tp, const Callback& cb, const void* scope)
{
    m_queue.emplace(queue_type::value_type { tp, cb, scope });
}

void Runtime::schedule(Clock::duration d, const Callback& cb, const void* scope)
{
    schedule(m_now + d, cb, scope);
}

void Runtime::cancel(const std::string& name)
{
    auto name_match_range = m_queue.get<by_name>().equal_range(name);
    m_queue.get<by_name>().erase(name_match_range.first, name_match_range.second);
}

void Runtime::cancel(const void* scope)
{
    if (scope) {
        auto scope_match_range = m_queue.get<by_scope>().equal_range(scope);
        m_queue.get<by_scope>().erase(scope_match_range.first, scope_match_range.second);
    }
}

Clock::time_point Runtime::next() const
{
    Clock::time_point next_tp = Clock::time_point::max();
    if (!m_queue.empty()) {
        next_tp = m_queue.get<by_deadline>().begin()->deadline;
    }
    return next_tp;
}

const Clock::time_point& Runtime::now() const
{
    return m_now;
}

void Runtime::trigger(Clock::time_point tp)
{
    // require monotonic clock
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
    // process queue elements separately because callback might modify runtime
    while (!m_queue.empty()) {
        auto top = m_queue.get<by_deadline>().begin();
        const auto deadline = top->deadline; // copy of deadline on purpose (erase before callback)
        if (deadline <= m_now) {
            Callback cb = top->callback;
            m_queue.get<by_deadline>().erase(top);
            // callback invocation has to be last action because it might modify runtime
            cb(deadline);
        } else {
            break;
        }
    }
}

void Runtime::reset(Clock::time_point tp)
{
    m_now = tp;
    queue_type queue;
    swap(queue, m_queue);

    // invoke all callbacks once so they can re-schedule
    for (auto& item : queue) {
        const auto& deadline = item.deadline;
        auto& callback = item.callback;
        // callback might modify m_queue
        callback(deadline);
    }
}

} // namespace vanetza
