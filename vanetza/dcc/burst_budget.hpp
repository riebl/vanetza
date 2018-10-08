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

/**
 * BurstBudget: TRC restrictions for DP0 message bursts as per C2C-CC BSP.
 */
class BurstBudget
{
public:
    // these constants are given in C2C-CC Basic System Profile (last v1.3.0)
    static constexpr Clock::duration T_Burst = std::chrono::seconds(1);
    static constexpr Clock::duration T_BurstPeriod = std::chrono::seconds(10);
    static constexpr std::size_t N_Burst = 20;

    BurstBudget(const Clock::time_point&);
    ~BurstBudget();

    /**
     * Get current delay to remain in budget
     * \return shortest delay not exceeding budget
     */
    Clock::duration delay();

    /**
     * Notify budget of consumption
     */
    void notify();

    /**
     * Set upper limit of messages per burst
     * \param n burst limit
     */
    void burst_messages(std::size_t n);

    /**
     * Set maximum duration per burst
     * \param d burst duration
     */
    void burst_duration(Clock::duration d);

    /**
     * Set minimum duration between bursts
     * \param p burst period
     */
    void burst_period(Clock::duration p);

private:
    const Clock::time_point& m_clock;
    boost::circular_buffer<Clock::time_point> m_messages;
    Clock::duration m_burst_duration = T_Burst;
    Clock::duration m_burst_period = T_BurstPeriod;
};

} // namespace dcc
} // namespace vanetza

#endif /* BURST_BUDGET_HPP_U5GXDCZN */

