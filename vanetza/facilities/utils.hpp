#ifndef UTILS_HPP_K7Q3MZ2D
#define UTILS_HPP_K7Q3MZ2D

#include <boost/units/quantity.hpp>
#include <cmath>

namespace vanetza
{
namespace facilities
{

/**
 * Convert a quantity to another unit and round to the nearest integer
 *
 * Halfway values are rounded away from zero, as done by std::lround.
 *
 * \param q quantity to convert
 * \param unit target unit, e.g. units::si::centi * units::si::meter
 * \return rounded value
 */
template<typename T, typename U>
long lround(const boost::units::quantity<T>& q, const U&)
{
    return std::lround(boost::units::quantity<U>(q).value());
}

} // namespace facilities
} // namespace vanetza

#endif /* UTILS_HPP_K7Q3MZ2D */
