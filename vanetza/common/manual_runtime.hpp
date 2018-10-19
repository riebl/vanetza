#ifndef MANUAL_RUNTIME_HPP_IPFSK6ZA
#define MANUAL_RUNTIME_HPP_IPFSK6ZA

#include <vanetza/common/runtime.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>

namespace vanetza
{

/**
 * ManualRuntime is a manually triggered Runtime implementation.
 * Ensure that time progress is triggered monotonically!
 */
class ManualRuntime : public Runtime
{
public:
    ManualRuntime() = default;

    /**
     * Create runtime
     * \param init initialization value of internal clock
     */
    explicit ManualRuntime(Clock::time_point init);

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

    /**
     * Get time point of next scheduled event
     * \note time point might belong to an expired event, i.e. next() < now()
     * \return time point of next event or time_point::max if none
     */
    Clock::time_point next() const;

    // Runtime interface (see header there for details)
    void schedule(Clock::time_point, const Callback&, const void* = nullptr) override;
    void schedule(Clock::duration, const Callback&, const void* = nullptr) override;
    void cancel(const void* scope) override;
    Clock::time_point now() const override;

private:
    struct ScheduledCallback
    {
        ScheduledCallback(Clock::time_point tp, const Callback& cb, const void* scope) :
            deadline(tp), callback(cb), scope(scope) {}

        ScheduledCallback(const ScheduledCallback&) = delete;
        ScheduledCallback& operator=(const ScheduledCallback&) = delete;

        ScheduledCallback(ScheduledCallback&&) = default;
        ScheduledCallback& operator=(ScheduledCallback&&) = default;

        Clock::time_point deadline;
        Callback callback;
        const void* scope;
    };

    struct by_deadline {};
    using time_index = boost::multi_index::ordered_non_unique<
        boost::multi_index::tag<by_deadline>,
        boost::multi_index::member<ScheduledCallback, Clock::time_point, &ScheduledCallback::deadline>>;
    struct by_scope {};
    using scope_index = boost::multi_index::hashed_non_unique<
        boost::multi_index::tag<by_scope>,
        boost::multi_index::member<ScheduledCallback, const void*, &ScheduledCallback::scope>>;
    using queue_type = boost::multi_index_container<ScheduledCallback,
          boost::multi_index::indexed_by<time_index, scope_index>>;

    void trigger();

    Clock::time_point m_now;
    queue_type m_queue;
};

} // namespace vanetza

#endif /* MANUAL_RUNTIME_HPP_IPFSK6ZA */

