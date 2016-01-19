#ifndef RUNTIME_HPP_KHDIEMRN
#define RUNTIME_HPP_KHDIEMRN

#include <vanetza/common/clock.hpp>
#include <boost/optional/optional.hpp>
#include <functional>
#include <queue>
#include <tuple>

namespace vanetza
{

/**
 * Runtime provides current time and enables scheduling of tasks for later execution.
 *
 * Time progress has to be triggered explicitly through trigger methods.
 * All calls to Runtime and objects using the same Runtime have to be invoked from same thread!
 **/
class Runtime
{
public:
    using Callback = std::function<void(Clock::time_point)>;

    /**
     * Schedule callback for later invocation
     * \param tp invoke callback at this time point
     * \param cb callback
     */
    void schedule(Clock::time_point tp, const Callback& cb);

    /**
     * Schedule callback for later invocation
     * \param d duration from now until callback invocation
     * \param cb callback
     */
    void schedule(Clock::duration d, const Callback& cb);

    /**
     * Get time point of next scheduled event
     * \note time point might belong to an expired event, i.e. next() < now()
     * \return time point of next event or time_point::max if none
     */
    Clock::time_point next();

    /**
     * Get current time
     * \return current time
     */
    const Clock::time_point& now() const;

    /**
     * Trigger absolute time progress
     *
     * All expired callbacks will be invoked
     * \param tp new time point, has to be greater than now
     */
    void trigger(Clock::time_point tp);

    /**
     * Trigger relative time progress
     *
     * All expired callbacks will be invoked
     * \param d advance time by this duration
     */
    void trigger(Clock::duration d);

private:
    using ScheduledCallback = std::tuple<Clock::time_point, Callback>;

    struct sort_scheduled_callback
    {
        bool operator()(const ScheduledCallback&, const ScheduledCallback&);
    };

    void trigger();

    Clock::time_point m_now;
    std::priority_queue<ScheduledCallback,
        std::deque<ScheduledCallback>,
        sort_scheduled_callback
    > m_queue;
};

} // namespace vanetza

#endif /* RUNTIME_HPP_KHDIEMRN */

