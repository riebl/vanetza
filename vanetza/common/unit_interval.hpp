#ifndef UNIT_INTERVAL_HPP_BG1EK7QX
#define UNIT_INTERVAL_HPP_BG1EK7QX

#include <boost/operators.hpp>
#include <iterator>
#include <type_traits>

namespace vanetza
{

/**
 * UnitInterval represents a number within the unit interval [0.0, 1.0]
 *
 * UnitInterval is not an interval on its own but limits all numbers to this interval.
 * Mantissa (positive fractional part of a real number) behaves differently, thus:
 * - Mantissa(42.1234) = 0.1234
 * - UnitInterval(42.1234) = 1.0
 * UnitInterval is also related to "(proper) decimal fraction" but latter does not include 1.0.
 */
class UnitInterval :
    boost::arithmetic<UnitInterval>,
    boost::arithmetic<UnitInterval, double>,
    boost::totally_ordered<UnitInterval>
{
public:
    constexpr UnitInterval() : UnitInterval(0.0) {}
    constexpr explicit UnitInterval(double v) : m_value(clamp(v)) {}
    UnitInterval(const UnitInterval&) = default;
    UnitInterval& operator=(const UnitInterval&) = default;

    // arithmetic
    UnitInterval& operator+=(const UnitInterval&);
    UnitInterval& operator-=(const UnitInterval&);
    UnitInterval& operator*=(const UnitInterval&);
    UnitInterval& operator/=(const UnitInterval&);

    UnitInterval& operator+=(double);
    UnitInterval& operator-=(double);
    UnitInterval& operator*=(double);
    UnitInterval& operator/=(double);

    // partially ordered
    bool operator<(const UnitInterval& other) const;
    bool operator==(const UnitInterval& other) const;

    double value() const { return m_value; }
    UnitInterval complement() const;

private:
    constexpr static double clamp(double v)
    {
        return (v > 1.0 ? 1.0 : (v < 0.0 ? 0.0 : v));
    }
    UnitInterval& clamp();

    double m_value;
};

/**
 * Calculate mean value of two unit intervals
 * \param lhs
 * \param rhs
 * \return mean unit interval
 */
UnitInterval mean(UnitInterval lhs, UnitInterval rhs);

/**
 * Calculate mean of a range of unit intervals
 * \param begin of range
 * \params end of range
 * \reutrn mean unit interval
 */
template<
    typename Iterator,
    typename std::enable_if<
        std::is_convertible<typename std::iterator_traits<Iterator>::value_type, UnitInterval>::value,
        int>::type = 0
>
UnitInterval mean(Iterator begin, Iterator end)
{
    unsigned count = 0;
    double accu = 0.0;

    for (Iterator it = begin; it != end; ++it)
    {
        accu += it->value();
        ++count;
    }

    return UnitInterval { count > 1 ? (accu / count) : accu };
}

} // namespace vanetza

#endif /* UNIT_INTERVAL_HPP_BG1EK7QX */

