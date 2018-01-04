#ifndef RUNTIME_HPP_KHDIEMRN
#define RUNTIME_HPP_KHDIEMRN

#include <vanetza/common/clock.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <functional>
#include <string>

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

    Runtime() = default;

    /**
     * Create runtime
     * \param init initialization value of internal clock
     */
    explicit Runtime(Clock::time_point init);

    /**
     * Schedule callback for later invocation
     * \param tp invoke callback at this time point
     * \param cb callback
     * \param name optional callback name
     */
    void schedule(Clock::time_point tp, const Callback& cb, const std::string& name = "");

    /**
     * Schedule callback for later invocation
     * \param d duration from now until callback invocation
     * \param cb callback
     * \param name optional callback name
     */
    void schedule(Clock::duration d, const Callback& cb, const std::string& name = "");

    /**
     * Schedule callback for later invocation
     * \param tp invoke callback at this time point
     * \param cb callback
     * \param scope associated scope pointer (used only for identification)
     */
    void schedule(Clock::time_point tp, const Callback& cb, const void* scope);

    /**
     * Schedule callback for later invocation
     * \param d duration from now until callback invocation
     * \param cb callback
     * \param scope associated scope pointer (used only for identification)
     */
    void schedule(Clock::duration d, const Callback& cb, const void* scope);

    /**
     * Cancel all scheduled invocations of a named callback
     * \param name Name of callback
     */
    void cancel(const std::string& name);

    /**
     * Cancel all scheduled invocations assigned to certain scope
     * \param scope any pointer used as scope at scheduling (nullptr has no effect)
     */
    void cancel(const void* scope);

    /**
     * Get time point of next scheduled event
     * \note time point might belong to an expired event, i.e. next() < now()
     * \return time point of next event or time_point::max if none
     */
    Clock::time_point next() const;

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

    /**
     * Reset runtime
     *
     * Drops all scheduled callbacks and resets internal clock
     * \param tp new time point
     */
    void reset(Clock::time_point tp);

private:
    struct ScheduledCallback
    {
        ScheduledCallback(Clock::time_point tp, const Callback& cb, const std::string& name) :
            deadline(tp), callback(cb), name(name), scope(nullptr) {}
        ScheduledCallback(Clock::time_point tp, const Callback& cb, const void* scope) :
            deadline(tp), callback(cb), scope(scope) {}

        ScheduledCallback(const ScheduledCallback&) = delete;
        ScheduledCallback& operator=(const ScheduledCallback&) = delete;

        ScheduledCallback(ScheduledCallback&&) = default;
        ScheduledCallback& operator=(ScheduledCallback&&) = default;

        Clock::time_point deadline;
        Callback callback;
        std::string name;
        const void* scope;
    };

    struct by_deadline {};
    using time_index = boost::multi_index::ordered_non_unique<
        boost::multi_index::tag<by_deadline>,
        boost::multi_index::member<ScheduledCallback, Clock::time_point, &ScheduledCallback::deadline>>;
    struct by_name {};
    using name_index = boost::multi_index::hashed_non_unique<
        boost::multi_index::tag<by_name>,
        boost::multi_index::member<ScheduledCallback, std::string, &ScheduledCallback::name>>;
    struct by_scope {};
    using scope_index = boost::multi_index::hashed_non_unique<
        boost::multi_index::tag<by_scope>,
        boost::multi_index::member<ScheduledCallback, const void*, &ScheduledCallback::scope>>;
    using queue_type = boost::multi_index_container<ScheduledCallback,
          boost::multi_index::indexed_by<time_index, name_index, scope_index>>;

    void trigger();

    Clock::time_point m_now;
    queue_type m_queue;
};

} // namespace vanetza

#endif /* RUNTIME_HPP_KHDIEMRN */

