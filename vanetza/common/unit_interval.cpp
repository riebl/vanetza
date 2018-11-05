#include <vanetza/common/unit_interval.hpp>
#include <algorithm>
#include <cmath>
#include <limits>

namespace vanetza
{

UnitInterval& UnitInterval::operator+=(const UnitInterval& other)
{
    m_value += other.m_value;
    return clamp();
}

UnitInterval& UnitInterval::operator-=(const UnitInterval& other)
{
    m_value -= other.m_value;
    return clamp();
}

UnitInterval& UnitInterval::operator*=(const UnitInterval& other)
{
    m_value *= other.m_value;
    // all unit interval multiplications remain within range
    return *this;
}

UnitInterval& UnitInterval::operator/=(const UnitInterval& other)
{
    m_value /= other.m_value;
    // only upper limit has to be enforced
    m_value = std::min(m_value, 1.0);
    return *this;
}

UnitInterval& UnitInterval::operator+=(double value)
{
    m_value += value;
    return clamp();
}

UnitInterval& UnitInterval::operator-=(double value)
{
    m_value -= value;
    return clamp();
}

UnitInterval& UnitInterval::operator*=(double value)
{
    m_value *= value;
    return clamp();
}

UnitInterval& UnitInterval::operator/=(double value)
{
    m_value /= value;
    return clamp();
}

bool UnitInterval::operator<(const UnitInterval& other) const
{
    return m_value < other.m_value;
}

bool UnitInterval::operator==(const UnitInterval& other) const
{
    // epsilon should be fine for values in [0.0, 1.0]
    return std::abs(m_value - other.m_value) < std::numeric_limits<double>::epsilon();
}

UnitInterval& UnitInterval::clamp()
{
    m_value = clamp(m_value);
    return *this;
}

UnitInterval UnitInterval::complement() const
{
    UnitInterval complement;
    complement.m_value = 1.0 - m_value;
    return complement;
}

UnitInterval mean(UnitInterval lhs, UnitInterval rhs)
{
    return UnitInterval { 0.5 * (lhs.value() + rhs.value()) };
}

} // namespace vanetza
