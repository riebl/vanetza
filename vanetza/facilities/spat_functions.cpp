#include <vanetza/facilities/spat_functions.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <array>
#include <chrono>

namespace vanetza
{
namespace facilities
{

const long cMinuteOfTheYearUnknown = 527040;
const long cTimeMarkOutOfRange = 36000;
const long cTimeMarkUnknown = 36001;

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
    const char* utc_since;
    long seconds;
};

// TAI - UTC since the 2004 epoch of Clock (IERS Bulletin C), extend when a leap second is announced
const std::array<TaiUtcOffset, 6> tai_utc_offsets {{
    { "2004-01-01 00:00:00", 32 },
    { "2006-01-01 00:00:00", 33 },
    { "2009-01-01 00:00:00", 34 },
    { "2012-07-01 00:00:00", 35 },
    { "2015-07-01 00:00:00", 36 },
    { "2017-01-01 00:00:00", 37 },
}};

} // namespace

Clock::time_point utc_from_tai(const Clock::time_point& tai)
{
    const ptime tai_time = Clock::at(tai);
    long offset = tai_utc_offsets.front().seconds;
    for (const TaiUtcOffset& entry : tai_utc_offsets) {
        const ptime switch_in_tai = boost::posix_time::time_from_string(entry.utc_since) +
            boost::posix_time::seconds(entry.seconds);
        if (tai_time >= switch_in_tai) {
            offset = entry.seconds;
        }
    }
    return tai - std::chrono::seconds(offset);
}

long minute_of_the_year(const Clock::time_point& at)
{
    const ptime t = Clock::at(at);
    const ptime year_begin { boost::gregorian::date(t.date().year(), 1, 1) };
    return static_cast<long>((t - year_begin).total_seconds() / 60);
}

long dsecond(const Clock::time_point& at)
{
    const time_duration tod = Clock::at(at).time_of_day();
    const time_duration since_minute = tod - boost::posix_time::hours(tod.hours()) - boost::posix_time::minutes(tod.minutes());
    return static_cast<long>(since_minute.total_milliseconds());
}

long time_mark(const Clock::time_point& at)
{
    return static_cast<long>(since_hour(Clock::at(at)).total_milliseconds() / 100);
}

boost::optional<Clock::time_point> time_mark_to_time_point(long mark, const Clock::time_point& reference)
{
    if (mark < 0 || mark >= cTimeMarkOutOfRange) {
        return boost::none;
    }

    const ptime ref = Clock::at(reference);
    const time_duration in_hour = since_hour(ref);
    const ptime hour_begin = ref - in_hour;
    ptime resolved = hour_begin + boost::posix_time::milliseconds(mark * 100);

    // marks before the begin of the reference minute belong to the following hour
    const long minute_begin = static_cast<long>(in_hour.minutes()) * 600;
    if (mark < minute_begin) {
        resolved += boost::posix_time::hours(1);
    }
    return Clock::at(resolved);
}

} // namespace facilities
} // namespace vanetza
