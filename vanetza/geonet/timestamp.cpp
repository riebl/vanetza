#include "timestamp.hpp"
#include <boost/date_time/gregorian/gregorian.hpp>
#include <cassert>
#include <limits>

namespace vanetza
{
namespace geonet
{

const Timestamp::unit_type Timestamp::millisecond;

const boost::posix_time::ptime Timestamp::start_time {
    boost::gregorian::date(2004, 1, 1),
    boost::posix_time::milliseconds(0)
};

Timestamp::Timestamp(const boost::posix_time::ptime& time)
{
    assert(time >= start_time);
    const value_type since_start_ms = (time - start_time).total_milliseconds();
    m_timestamp = since_start_ms * absolute_unit_type();
}

bool is_greater(Timestamp lhs, Timestamp rhs)
{
    const auto max = std::numeric_limits<Timestamp::value_type>::max();
    const Timestamp::value_type lhs_raw = lhs.raw();
    const Timestamp::value_type rhs_raw = rhs.raw();

    if ((lhs_raw > rhs_raw && lhs_raw - rhs_raw <= max/2) ||
        (rhs_raw > lhs_raw && rhs_raw - lhs_raw > max/2)) {
        return true;
    } else {
        return false;
    }
}

bool operator<(Timestamp lhs, Timestamp rhs)
{
    return (!is_greater(lhs, rhs) && lhs != rhs);
}

bool operator==(Timestamp lhs, Timestamp rhs)
{
    return lhs.raw() == rhs.raw();
}

} // namespace geonet
} // namespace vanetza

