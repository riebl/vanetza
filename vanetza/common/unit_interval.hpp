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
 */
class UnitInterval :
    boost::arithmetic<UnitInterval>,
    boost::arithmetic<UnitInterval, double>,
    boost::totally_ordered<UnitInterval>
{
public:
    UnitInterval();
    UnitInterval(const UnitInterval&) = default;
    UnitInterval& operator=(const UnitInterval&) = default;
    explicit UnitInterval(double);
    UnitInterval& operator=(double);

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
    UnitInterval& clamp();
    double m_value;
};

} // namespace vanetza

#endif /* UNIT_INTERVAL_HPP_BG1EK7QX */

