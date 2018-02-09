#ifndef POSITION_CONFIDENCE_HPP_FNHKVJZL
#define POSITION_CONFIDENCE_HPP_FNHKVJZL

#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>
#include <cmath>
#include <limits>

namespace vanetza
{

struct PositionConfidence
{
    PositionConfidence() :
        semi_major(units::Length::from_value(std::numeric_limits<units::Length::value_type>::infinity())),
        semi_minor(units::Length::from_value(std::numeric_limits<units::Length::value_type>::infinity()))
    {}

    operator bool() const
    {
        return !std::isinf(semi_major.value()) && semi_minor.value() <= semi_major.value() && semi_minor.value() >= 0.0;
    }

    units::Length semi_major;
    units::Length semi_minor;
    units::TrueNorth orientation;
};

} // namespace vanetza

#endif /* POSITION_CONFIDENCE_HPP_FNHKVJZL */

