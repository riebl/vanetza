#ifndef UNIT_INTERVAL_HPP_BG1EK7QX
#define UNIT_INTERVAL_HPP_BG1EK7QX

#include <boost/operators.hpp>

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

} // namespace vanetza

#endif /* UNIT_INTERVAL_HPP_BG1EK7QX */

