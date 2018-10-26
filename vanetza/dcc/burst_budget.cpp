#include <vanetza/common/runtime.hpp>
#include <vanetza/dcc/burst_budget.hpp>
#include <cassert>

namespace vanetza
{
namespace dcc
{

namespace
{
// these constants are given in C2C-CC Basic System Profile (last v1.3.0)
constexpr Clock::duration T_Burst = std::chrono::seconds(1);
constexpr Clock::duration T_BurstPeriod = std::chrono::seconds(10);
constexpr std::size_t N_Burst = 20;
} // namespace


BurstBudget::BurstBudget(const Runtime& rt) :
    m_runtime(rt), m_messages(N_Burst), m_burst_duration(T_Burst), m_burst_period(T_BurstPeriod)
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
