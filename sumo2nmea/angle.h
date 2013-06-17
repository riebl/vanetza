#ifndef ANGLE_H_QWPLNJ3B
#define ANGLE_H_QWPLNJ3B

#include <boost/math/constants/constants.hpp>

namespace units {

struct degree {};
struct radian {};

static const degree deg;
static const radian rad;

} // namespace units


template<typename FROM, typename TO, typename T>
struct conversion_helper;

template<typename T>
struct conversion_helper<units::radian, units::degree, T>
{
    static T convert(const T& rad)
    {
        return rad / boost::math::constants::pi<T>() * 180.0;
    }
};


template<typename UNIT, typename T = double>
class Angle
{
    public:
    typedef T value_type;

    explicit Angle(T numeric) : m_value(numeric) {}

    template<typename OTHER_UNIT, typename OTHER_TYPE>
    Angle(const Angle<OTHER_UNIT, OTHER_TYPE>& other) :
        m_value(conversion_helper<OTHER_UNIT, UNIT, T>::convert(other.value()))
    {
    }

    T value() const { return m_value; }

    private:
    T m_value;
};

typedef Angle<units::degree> AngleDegree;
typedef Angle<units::radian> AngleRadian;

template<typename UNIT>
Angle<UNIT> operator%(typename Angle<UNIT>::value_type numeric, UNIT u)
{
    return Angle<UNIT>(numeric);
}

#endif /* ANGLE_H_QWPLNJ3B */

