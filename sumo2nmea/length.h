#ifndef LENGTH_H_56IO9TDB
#define LENGTH_H_56IO9TDB

#include "quantity.h"

namespace units
{
    struct meter {};
    static const meter m;
} // namespace units

class Length : public Quantity<double>
{
    public:
    using Quantity<double>::Quantity;
};

typedef Length LengthMeter;

#endif /* LENGTH_H_56IO9TDB */

