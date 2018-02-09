#ifndef POSITION_FIX_HPP_BGU14Q9D
#define POSITION_FIX_HPP_BGU14Q9D

#include <vanetza/common/clock.hpp>
#include <vanetza/common/confident_quantity.hpp>
#include <vanetza/common/position_confidence.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/velocity.hpp>

namespace vanetza
{

struct PositionFix
{
    Clock::time_point timestamp;
    units::GeoAngle latitude;
    units::GeoAngle longitude;
    PositionConfidence confidence;
    ConfidentQuantity<units::TrueNorth> course;
    ConfidentQuantity<units::Velocity> speed;
};

} // namespace vanetza

#endif /* POSITION_FIX_HPP_BGU14Q9D */

