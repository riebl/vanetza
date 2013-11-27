#ifndef LENGTH_H_56IO9TDB
#define LENGTH_H_56IO9TDB

#include <vanetza/units/quantity.h>

namespace vanetza
{

namespace units
{
    struct meter {};
    static const meter m;
} // namespace units

class Length : public Quantity<double>
{
    public:
    // TODO: Requires gcc 4.8
    // using Quantity<double>::Quantity;
    explicit Length(double value) : Quantity<double>(value) {}
};

typedef Length LengthMeter;

} // namespace vanetza

#endif /* LENGTH_H_56IO9TDB */

