#ifndef BURST_BUDGET_HPP_U5GXDCZN
#define BURST_BUDGET_HPP_U5GXDCZN

#include <vanetza/common/clock.hpp>
#include <boost/circular_buffer.hpp>
#include <chrono>
#include <cstddef>

namespace vanetza
{

// forward declaration
class Runtime;

namespace dcc
{

/**
 * BurstBudget: TRC restrictions for DP0 message bursts as per C2C-CC BSP.
 */
class BurstBudget
{
public:
    BurstBudget(const Runtime&);
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

    /**
     * Get burst interval
     * \return bust interval
     */
    Clock::duration burst_period() const { return m_burst_period; }

private:
    const Runtime& m_runtime;
    boost::circular_buffer<Clock::time_point> m_messages;
    Clock::duration m_burst_duration;
    Clock::duration m_burst_period;
};

} // namespace dcc
} // namespace vanetza

#endif /* BURST_BUDGET_HPP_U5GXDCZN */

