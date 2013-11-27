#ifndef ANGLE_H_QWPLNJ3B
#define ANGLE_H_QWPLNJ3B

#include "vanetza/units/quantity.h"
#include "vanetza/units/unit.h"
#include <boost/math/constants/constants.hpp>

namespace vanetza
{
namespace units
{

struct degree {};
struct radian {};

static const degree deg;
static const radian rad;

} // namespace units


template<typename T>
struct conversion_helper<units::radian, units::degree, T>
{
    static T convert(const T& rad)
    {
        return rad / boost::math::constants::pi<T>() * 180.0;
    }
};


template<typename UNIT, typename T = double>
class Angle : public Quantity<T>
{
    public:
    explicit Angle(T numeric) : Quantity<T>(numeric) {}

    template<typename OTHER_UNIT, typename OTHER_TYPE>
    Angle(const Angle<OTHER_UNIT, OTHER_TYPE>& other) :
        Quantity<T>(conversion_helper<OTHER_UNIT, UNIT, T>::convert(other.value()))
    {
    }
};

VANETZA_UNIT(Angle, units::degree, AngleDegree)
VANETZA_UNIT(Angle, units::radian, AngleRadian)

} // namespace vanetza

#endif /* ANGLE_H_QWPLNJ3B */

