#include "burst_budget.hpp"

namespace vanetza
{
namespace dcc
{

BurstBudget::BurstBudget(const clock::time_point& clock) :
    m_clock(clock), m_bursts(N_Burst)
{
}

clock::duration BurstBudget::delay()
{
    clock::duration delay = clock::duration::max();

    if (m_bursts.empty()) {
        delay = clock::duration::zero();
    } else if (m_bursts.front() + T_Burst > m_clock && !m_bursts.full()) {
        delay = clock::duration::zero();
    } else if (m_bursts.front() + T_BurstPeriod < m_clock) {
        m_bursts.clear();
        delay = clock::duration::zero();
    } else {
        delay = m_bursts.front() + T_BurstPeriod - m_clock;
    }

    return delay;
}

void BurstBudget::notify()
{
    m_bursts.push_back(m_clock);
}

} // namespace dcc
} // namespace vanetza
