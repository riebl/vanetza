#ifndef RUNTIME_HPP_KHDIEMRN
#define RUNTIME_HPP_KHDIEMRN

#include <vanetza/common/clock.hpp>
#include <functional>

namespace vanetza
{

/**
 * Runtime provides current time and enables scheduling of tasks for later execution.
 *
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
     * \param scope associated scope pointer (used only for identification)
     */
    virtual void schedule(Clock::time_point tp, const Callback& cb, const void* scope = nullptr) = 0;

    /**
     * Schedule callback for later invocation
     * \param d duration from now until callback invocation
     * \param cb callback
     * \param scope associated scope pointer (used only for identification)
     */
    virtual void schedule(Clock::duration d, const Callback& cb, const void* scope = nullptr) = 0;

    /**
     * Cancel all scheduled invocations assigned to certain scope
     * \param scope any pointer used as scope at scheduling (nullptr has no effect)
     */
    virtual void cancel(const void* scope) = 0;

    /**
     * Get current time
     * \return current time
     */
    virtual Clock::time_point now() const = 0;

    virtual ~Runtime() = default;
};

} // namespace vanetza

#endif /* RUNTIME_HPP_KHDIEMRN */

