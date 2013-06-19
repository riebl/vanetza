#ifndef VELOCITY_H_0BLFAIDT
#define VELOCITY_H_0BLFAIDT

#include "quantity.h"

namespace units
{
    struct knots {};
    static const knots kn;
} // namespace units

class Velocity : public Quantity<double>
{
    public:
    using Quantity<double>::Quantity;
};

typedef Velocity VelocityKnot;

#endif /* VELOCITY_H_0BLFAIDT */

