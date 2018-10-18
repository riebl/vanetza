#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/burst_budget.hpp>
#include <cassert>

namespace vanetza
{
namespace dcc
{

BurstBudget::BurstBudget(const Runtime& rt) :
    m_runtime(rt), m_messages(N_Burst)
{
}

BurstBudget::~BurstBudget()
{
}

Clock::duration BurstBudget::delay()
{
    assert(m_burst_duration < m_burst_period);
    Clock::duration delay = Clock::duration::max();

    if (m_messages.empty()) {
        delay = Clock::duration::zero();
    } else if (m_messages.front() + m_burst_duration > m_runtime.now() && !m_messages.full()) {
        delay = Clock::duration::zero();
    } else if (m_messages.front() + m_burst_period < m_runtime.now()) {
        m_messages.clear();
        delay = Clock::duration::zero();
    } else {
        delay = m_messages.front() + m_burst_period - m_runtime.now();
    }

    return delay;
}

void BurstBudget::notify()
{
    m_messages.push_back(m_runtime.now());
}

void BurstBudget::burst_messages(std::size_t n)
{
    // circular_buffer::resize removes last elements if necessary
    m_messages.resize(n);
}

void BurstBudget::burst_duration(Clock::duration d)
{
    assert(d > Clock::duration::zero());
    m_burst_duration = d;
}

void BurstBudget::burst_period(Clock::duration p)
{
    assert(p > Clock::duration::zero());
    m_burst_period = p;
}

} // namespace dcc
} // namespace vanetza
