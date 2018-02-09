#ifndef CONFIDENT_QUANTITY_HPP_B2XVJERI
#define CONFIDENT_QUANTITY_HPP_B2XVJERI

#include <limits>

namespace vanetza
{

/**
 * ConfidentQuantity combines a boost::quantity value with a confidence level.
 *
 * Usually, a confidence level of 95% is used in ITS specifications.
 * If no confidence level is explicitly given a worst case value is used, i.e.
 * the maximum value representable by the underlying type or infinity.
 */
template<typename T>
class ConfidentQuantity
{
public:
    constexpr T worst_confidence() const
    {
        using value_type = typename T::value_type;
        return T::from_value(std::numeric_limits<value_type>::has_infinity ?
            std::numeric_limits<value_type>::infinity() :
            std::numeric_limits<value_type>::max());
    }

    constexpr T default_value() const
    {
        using value_type = typename T::value_type;
        return T::from_value(std::numeric_limits<value_type>::has_quiet_NaN ?
            std::numeric_limits<value_type>::quiet_NaN() : value_type());
    }

    constexpr bool is_nan(const T& t) const
    {
        return t.value() != t.value();
    }

    ConfidentQuantity() :
        m_value(default_value()), m_confidence(worst_confidence()) {}
    ConfidentQuantity(const T& value) :
        m_value(value), m_confidence(worst_confidence()) {}
    ConfidentQuantity(const T& value, const T& confidence) :
        m_value(value), m_confidence(!is_nan(confidence) ? confidence : worst_confidence()) {}

    ConfidentQuantity(const ConfidentQuantity&) = default;
    ConfidentQuantity& operator=(const ConfidentQuantity&) = default;
    ConfidentQuantity(ConfidentQuantity&&) = default;
    ConfidentQuantity& operator=(ConfidentQuantity&&) = default;

    void assign(const T& value, const T& confidence)
    {
        m_value = value;
        m_confidence = !is_nan(confidence) ? confidence : worst_confidence();
    }

    const T& value() const
    {
        return m_value;
    }

    const T& confidence() const
    {
        return m_confidence;
    }

private:
    T m_value;
    T m_confidence;
};


} // namespace vanetza

#endif /* CONFIDENT_QUANTITY_HPP_B2XVJERI */

