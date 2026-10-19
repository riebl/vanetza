#include <vanetza/facilities/spat_functions.hpp>
#include <vanetza/asn1/its/asn_constant.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <array>

namespace vanetza
{
namespace facilities
{

const std::chrono::minutes cMinuteOfTheYearUnknown { max_val_MinuteOfTheYear };
// TimeMark values given by C2C-CC RS 2077 (parameter settings) as well:
// pTimeMarkOutOfRange 36000 and pTimeMarkUnknown 36001
const TimeMark cTimeMarkOutOfRange { max_val_TimeMark - 1 };
const TimeMark cTimeMarkUnknown { max_val_TimeMark };

namespace
{

using boost::posix_time::ptime;
using boost::posix_time::time_duration;

time_duration since_hour(const ptime& t)
{
    const time_duration tod = t.time_of_day();
    return tod - boost::posix_time::hours(tod.hours());
}

struct TaiUtcOffset
{
    ptime utc_since;
    std::chrono::seconds offset;
};

// TAI - UTC since the 2004 epoch of Clock (IERS Bulletin C), extend when a leap second is announced
const std::array<TaiUtcOffset, 6> tai_utc_offsets {{
    { ptime { boost::gregorian::date(2004, 1, 1) }, std::chrono::seconds(32) },
    { ptime { boost::gregorian::date(2006, 1, 1) }, std::chrono::seconds(33) },
    { ptime { boost::gregorian::date(2009, 1, 1) }, std::chrono::seconds(34) },
    { ptime { boost::gregorian::date(2012, 7, 1) }, std::chrono::seconds(35) },
    { ptime { boost::gregorian::date(2015, 7, 1) }, std::chrono::seconds(36) },
    { ptime { boost::gregorian::date(2017, 1, 1) }, std::chrono::seconds(37) },
}};

} // namespace

Clock::time_point utc_from_tai(const Clock::time_point& tai)
{
    std::chrono::seconds offset = tai_utc_offsets.front().offset;
    for (const TaiUtcOffset& entry : tai_utc_offsets) {
        if (tai >= Clock::at(entry.utc_since) + entry.offset) {
            offset = entry.offset;
        }
    }
    return tai - offset;
}

std::chrono::minutes minute_of_the_year(const Clock::time_point& at)
{
    const ptime year_begin { boost::gregorian::date(Clock::at(at).date().year(), 1, 1) };
    return std::chrono::duration_cast<std::chrono::minutes>(at - Clock::at(year_begin));
}

std::chrono::milliseconds dsecond(const Clock::time_point& at)
{
    const time_duration tod = Clock::at(at).time_of_day();
    const time_duration since_minute = tod - boost::posix_time::hours(tod.hours()) - boost::posix_time::minutes(tod.minutes());
    return std::chrono::milliseconds(since_minute.total_milliseconds());
}

TimeMark time_mark(const Clock::time_point& at)
{
    const std::chrono::milliseconds in_hour { since_hour(Clock::at(at)).total_milliseconds() };
    return std::chrono::duration_cast<TimeMark>(in_hour);
}

boost::optional<Clock::time_point> time_mark_to_time_point(TimeMark mark, const Clock::time_point& reference)
{
    if (mark < TimeMark::zero() || mark >= cTimeMarkOutOfRange) {
        return boost::none;
    }

    const ptime ref = Clock::at(reference);
    const time_duration in_hour = since_hour(ref);
    Clock::time_point resolved = Clock::at(ref - in_hour) + mark;

    // marks before the begin of the reference minute belong to the following hour
    if (mark < std::chrono::minutes(in_hour.minutes())) {
        resolved += std::chrono::hours(1);
    }
    return resolved;
}

} // namespace facilities
} // namespace vanetza
