#ifndef VELOCITY_H_0BLFAIDT
#define VELOCITY_H_0BLFAIDT

#include <vanetza/units/quantity.h>
#include <vanetza/units/unit.h>

namespace vanetza
{

namespace units
{
    struct knots {};
    struct meter_per_second {};
    static const knots kn;
    static const meter_per_second mps;
} // namespace units

namespace constants
{
    static const unsigned cNauticalMileInMeters = 1852;
} // namespace constants

template<typename T>
struct conversion_helper<units::meter_per_second, units::knots, T>
{
    static T convert(const T& mps)
    {
        return (mps * 3600) / constants::cNauticalMileInMeters;
    }
};

template<typename UNIT>
class Velocity : public Quantity<double>
{
    public:
    // TODO: requires gcc 4.8
    // using Quantity<double>::Quantity;
    explicit Velocity(double value) : Quantity<double>(value) {}

    // TODO: implement generic conversion
    template<typename OTHER_UNIT>
    Velocity(const Velocity<OTHER_UNIT>& other) :
        Quantity<double>(conversion_helper<OTHER_UNIT, UNIT, double>::convert(other.value()))
    {
    }
};

typedef Velocity<units::knots> VelocityKnot;
typedef Velocity<units::meter_per_second> VelocityMps;

} // namespace vanetza

#endif /* VELOCITY_H_0BLFAIDT */

