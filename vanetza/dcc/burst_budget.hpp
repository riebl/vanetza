#ifndef BURST_BUDGET_HPP_U5GXDCZN
#define BURST_BUDGET_HPP_U5GXDCZN

#include <vanetza/common/clock.hpp>
#include <boost/circular_buffer.hpp>
#include <chrono>
#include <cstddef>

namespace vanetza
{
namespace dcc
{

static const clock::duration T_Burst = std::chrono::seconds(1);
static const clock::duration T_BurstPeriod = std::chrono::seconds(10);
constexpr std::size_t N_Burst = 20;

class BurstBudget
{
public:
    BurstBudget(const clock::time_point&);
    ~BurstBudget();

    /**
     * Get current delay to remain in budget
     * \return shortest delay not exceeding budget
     */
    clock::duration delay();

    /**
     * Notify budget of consumption
     */
    void notify();

private:
    const clock::time_point& m_clock;
    boost::circular_buffer<clock::time_point> m_bursts;
};

} // namespace dcc
} // namespace vanetza

#endif /* BURST_BUDGET_HPP_U5GXDCZN */

