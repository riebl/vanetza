#ifndef EXPECTED_HPP_Q7RM4KZD
#define EXPECTED_HPP_Q7RM4KZD

#include <cassert>
#include <cstdlib>
#include <exception>
#include <memory>
#include <new>
#include <system_error>
#include <type_traits>
#include <utility>

#if defined(__has_include)
#   if __has_include(<version>)
#       include <version>
#   endif
#endif

#if defined(__cpp_lib_expected)
#   include <expected>
#endif

#if defined(__has_cpp_attribute)
#   if __has_cpp_attribute(nodiscard)
#       define VANETZA_EXPECTED_NODISCARD [[nodiscard]]
#   endif
#endif
#ifndef VANETZA_EXPECTED_NODISCARD
#   define VANETZA_EXPECTED_NODISCARD
#endif

namespace vanetza
{

/**
 * Error wrapper for constructing an expected holding an error (mimics std::unexpected)
 */
template<typename E>
class unexpected
{
public:
    explicit unexpected(const E& error) : m_error(error) {}
    explicit unexpected(E&& error) : m_error(std::move(error)) {}

    const E& error() const& noexcept { return m_error; }
    E& error() & noexcept { return m_error; }
    E&& error() && noexcept { return std::move(m_error); }

private:
    E m_error;
};

template<typename E>
class bad_expected_access;

template<>
class bad_expected_access<void> : public std::exception
{
public:
    const char* what() const noexcept override
    {
        return "bad access to vanetza::expected without expected value";
    }
};

/**
 * Exception thrown when accessing the value of an expected holding an error
 */
template<typename E>
class bad_expected_access : public bad_expected_access<void>
{
public:
    explicit bad_expected_access(E error) : m_error(std::move(error)) {}

    const E& error() const& noexcept { return m_error; }
    E& error() & noexcept { return m_error; }

private:
    E m_error;
};

namespace detail
{

template<typename T>
struct is_unexpected : std::false_type {};

template<typename E>
struct is_unexpected<unexpected<E>> : std::true_type {};

template<typename E>
bad_expected_access<E> make_bad_expected_access(const E& error)
{
    return bad_expected_access<E>(error);
}

// error codes carry their message: use the matching standard exception
inline std::system_error make_bad_expected_access(const std::error_code& error)
{
    return std::system_error(error);
}

// aborts if exceptions are disabled, e.g. by -fno-exceptions
template<typename E>
[[noreturn]] void throw_bad_expected_access(const E& error)
{
#if defined(__cpp_exceptions)
    throw make_bad_expected_access(error);
#else
    static_cast<void>(error);
    std::abort();
#endif
}

} // namespace detail

/**
 * Either a value or an error (inspired by C++23 std::expected)
 */
template<typename T, typename E = std::error_code>
class VANETZA_EXPECTED_NODISCARD expected
{
    static_assert(!std::is_reference<T>::value, "expected cannot hold references");

public:
    using value_type = T;
    using error_type = E;
    using unexpected_type = unexpected<E>;

    expected() : m_value(), m_has_value(true) {}

    template<typename U = T, std::enable_if_t<
        std::is_convertible<U&&, T>::value && !std::is_convertible<U&&, E>::value &&
        !std::is_same<std::decay_t<U>, expected>::value &&
        !detail::is_unexpected<std::decay_t<U>>::value, int> = 0>
    expected(U&& value) : m_value(std::forward<U>(value)), m_has_value(true) {}

    template<typename G, std::enable_if_t<
        std::is_convertible<G&&, E>::value && !std::is_convertible<G&&, T>::value &&
        !std::is_same<std::decay_t<G>, expected>::value &&
        !detail::is_unexpected<std::decay_t<G>>::value, int> = 0>
    expected(G&& error) : m_error(std::forward<G>(error)), m_has_value(false) {}

    template<typename G, typename = std::enable_if_t<std::is_constructible<E, const G&>::value>>
    expected(const unexpected<G>& error) : m_error(error.error()), m_has_value(false) {}

    template<typename G, typename = std::enable_if_t<std::is_constructible<E, G&&>::value>>
    expected(unexpected<G>&& error) : m_error(std::move(error).error()), m_has_value(false) {}

    expected(const expected& other) { construct(other); }

    expected(expected&& other) noexcept(
        std::is_nothrow_move_constructible<T>::value && std::is_nothrow_move_constructible<E>::value)
    {
        construct(std::move(other));
    }

    ~expected() { destroy(); }

    expected& operator=(const expected& other)
    {
        if (m_has_value && other.m_has_value) {
            m_value = other.m_value;
        } else if (!m_has_value && !other.m_has_value) {
            m_error = other.m_error;
        } else {
            // copy first so this object stays intact if copying throws
            expected copy(other);
            replace(std::move(copy));
        }
        return *this;
    }

    expected& operator=(expected&& other) noexcept(
        std::is_nothrow_move_constructible<T>::value && std::is_nothrow_move_assignable<T>::value &&
        std::is_nothrow_move_constructible<E>::value && std::is_nothrow_move_assignable<E>::value)
    {
        if (m_has_value && other.m_has_value) {
            m_value = std::move(other.m_value);
        } else if (!m_has_value && !other.m_has_value) {
            m_error = std::move(other.m_error);
        } else {
            replace(std::move(other));
        }
        return *this;
    }

    bool has_value() const noexcept { return m_has_value; }
    bool has_error() const noexcept { return !m_has_value; }

    // not for bool values: std::expected<bool, E> would store has_value() when constructed from this expected
    template<typename U = T, typename = std::enable_if_t<!std::is_same<std::remove_cv_t<U>, bool>::value>>
    explicit operator bool() const noexcept { return m_has_value; }

    const T* operator->() const noexcept
    {
        assert(m_has_value);
        return std::addressof(m_value);
    }

    T* operator->() noexcept
    {
        assert(m_has_value);
        return std::addressof(m_value);
    }

    const T& operator*() const& noexcept
    {
        assert(m_has_value);
        return m_value;
    }

    T& operator*() & noexcept
    {
        assert(m_has_value);
        return m_value;
    }

    T&& operator*() && noexcept
    {
        assert(m_has_value);
        return std::move(m_value);
    }

    const T& value() const&
    {
        if (!m_has_value) {
            detail::throw_bad_expected_access(m_error);
        }
        return m_value;
    }

    T& value() &
    {
        if (!m_has_value) {
            detail::throw_bad_expected_access(m_error);
        }
        return m_value;
    }

    T&& value() &&
    {
        if (!m_has_value) {
            detail::throw_bad_expected_access(m_error);
        }
        return std::move(m_value);
    }

    const E& error() const& noexcept
    {
        assert(!m_has_value);
        return m_error;
    }

    E& error() & noexcept
    {
        assert(!m_has_value);
        return m_error;
    }

    E&& error() && noexcept
    {
        assert(!m_has_value);
        return std::move(m_error);
    }

    template<typename U>
    T value_or(U&& fallback) const&
    {
        return m_has_value ? m_value : static_cast<T>(std::forward<U>(fallback));
    }

    template<typename U>
    T value_or(U&& fallback) &&
    {
        return m_has_value ? std::move(m_value) : static_cast<T>(std::forward<U>(fallback));
    }

#if defined(__cpp_lib_expected)
    operator std::expected<T, E>() const&
    {
        if (m_has_value) {
            return std::expected<T, E>(std::in_place, m_value);
        } else {
            return std::expected<T, E>(std::unexpect, m_error);
        }
    }

    operator std::expected<T, E>() &&
    {
        if (m_has_value) {
            return std::expected<T, E>(std::in_place, std::move(m_value));
        } else {
            return std::expected<T, E>(std::unexpect, std::move(m_error));
        }
    }
#endif

private:
    template<typename Other>
    void construct(Other&& other)
    {
        m_has_value = other.m_has_value;
        if (m_has_value) {
            ::new (std::addressof(m_value)) T(std::forward<Other>(other).m_value);
        } else {
            ::new (std::addressof(m_error)) E(std::forward<Other>(other).m_error);
        }
    }

    void replace(expected&& other) noexcept
    {
        static_assert(std::is_nothrow_move_constructible<T>::value && std::is_nothrow_move_constructible<E>::value,
            "switching between value and error requires nothrow move construction");
        destroy();
        construct(std::move(other));
    }

    void destroy() noexcept
    {
        if (m_has_value) {
            m_value.~T();
        } else {
            m_error.~E();
        }
    }

    union
    {
        T m_value;
        E m_error;
    };
    bool m_has_value;
};

} // namespace vanetza

#undef VANETZA_EXPECTED_NODISCARD

#endif /* EXPECTED_HPP_Q7RM4KZD */
