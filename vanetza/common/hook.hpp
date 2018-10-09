#ifndef HOOK_HPP_RNAM6XF4
#define HOOK_HPP_RNAM6XF4

#include <functional>
#include <utility>

namespace vanetza
{

/**
 * Hook mechanism for realising extension points
 */
template<typename... Args>
class Hook
{
public:
    typedef std::function<void(Args...)> callback_type;

    /**
     * Assign a callback to hook, replaces previously assigned one
     * \param cb A callable used as hook callback, e.g. lambda
     */
    void operator=(callback_type&& cb)
    {
        m_function = std::move(cb);
    }

    void operator=(const callback_type& cb)
    {
        m_function = cb;
    }

    /**
     * Execute hook callback if assigned
     * \param Args... various arguments passed to assigned callback
     */
    void operator()(Args... args)
    {
        if (m_function) {
            // that's an arcane syntax, isn't it?
            m_function(std::forward<Args>(args)...);
        }
    }

    /**
     * Reset previously assigned callback.
     * No callback will be invoked when triggering hook after reset.
     */
    void reset()
    {
        m_function = nullptr;
    }

    /**
     * \deprecated previous name of reset
     */
    void clear() { reset(); }

private:
    callback_type m_function;
};

/**
 * Hook registry (non-callable view of a hook)
 *
 * Callbacks can be assigned to a hook via the corresponding registry,
 * but the callback cannot be invoked through the registry.
 */
template<typename... Args>
class HookRegistry
{
public:
    using hook_type = Hook<Args...>;
    using callback_type = typename hook_type::callback_type;

    HookRegistry(hook_type& hook) : m_hook(hook) {}

    void operator=(callback_type&& cb)
    {
        m_hook = std::move(cb);
    }

    void operator=(const callback_type& cb)
    {
        m_hook = cb;
    }

    void reset()
    {
        m_hook.reset();
    }

private:
    hook_type& m_hook;
};

} // namespace vanetza

#endif /* HOOK_HPP_RNAM6XF4 */

