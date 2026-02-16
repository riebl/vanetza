#include <vanetza/common/position_fix.hpp>
#include <boost/units/cmath.hpp>

namespace vanetza
{

bool has_horizontal_position(const PositionFix &posfix)
{
    using namespace boost::units;
    return isfinite(posfix.latitude) && isfinite(posfix.longitude);
}

} // namespace vanetza
