#include "time.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <charconv>
#include <functional>
#include <map>
#include <system_error>
#include <utility>

namespace vanetza
{
namespace pki
{

static std::pair<boost::posix_time::ptime, boost::posix_time::seconds>
leap_seconds_from(boost::gregorian::date start_of_validity, boost::posix_time::seconds leap)
{
    return std::make_pair(boost::posix_time::ptime { start_of_validity }, leap);
}

boost::posix_time::time_duration utc_tai_offset(boost::posix_time::ptime t)
{
    using date = boost::gregorian::date;
    using seconds = boost::posix_time::seconds;
    using posix_time = boost::posix_time::ptime;
    static const std::map<posix_time, seconds, std::greater<posix_time>> offsets {
        leap_seconds_from(date { 1972, 7, 1 }, seconds(11)),
        leap_seconds_from(date { 1973, 1, 1 }, seconds(12)),
        leap_seconds_from(date { 1974, 1, 1 }, seconds(13)),
        leap_seconds_from(date { 1975, 1, 1 }, seconds(14)),
        leap_seconds_from(date { 1976, 1, 1 }, seconds(15)),
        leap_seconds_from(date { 1977, 1, 1 }, seconds(16)),
        leap_seconds_from(date { 1978, 1, 1 }, seconds(17)),
        leap_seconds_from(date { 1979, 1, 1 }, seconds(18)),
        leap_seconds_from(date { 1980, 1, 1 }, seconds(19)),
        leap_seconds_from(date { 1981, 7, 1 }, seconds(20)),
        leap_seconds_from(date { 1982, 7, 1 }, seconds(21)),
        leap_seconds_from(date { 1983, 7, 1 }, seconds(22)),
        leap_seconds_from(date { 1985, 7, 1 }, seconds(23)),
        leap_seconds_from(date { 1988, 1, 1 }, seconds(24)),
        leap_seconds_from(date { 1990, 1, 1 }, seconds(25)),
        leap_seconds_from(date { 1991, 1, 1 }, seconds(26)),
        leap_seconds_from(date { 1992, 7, 1 }, seconds(27)),
        leap_seconds_from(date { 1993, 7, 1 }, seconds(28)),
        leap_seconds_from(date { 1994, 7, 1 }, seconds(29)),
        leap_seconds_from(date { 1996, 1, 1 }, seconds(30)),
        leap_seconds_from(date { 1997, 7, 1 }, seconds(31)),
        leap_seconds_from(date { 1999, 1, 1 }, seconds(32)),
        leap_seconds_from(date { 2006, 1, 1 }, seconds(33)),
        leap_seconds_from(date { 2009, 1, 1 }, seconds(34)),
        leap_seconds_from(date { 2012, 7, 1 }, seconds(35)),
        leap_seconds_from(date { 2015, 7, 1 }, seconds(36)),
        leap_seconds_from(date { 2017, 1, 1 }, seconds(37)),
    };

    auto found = offsets.lower_bound(t); // latest entry whose validity has begun at t
    return found != offsets.end() ? found->second : boost::posix_time::seconds(10);
}

Clock::time_point current_time()
{
    auto utc = boost::posix_time::microsec_clock::universal_time();
    static const auto leap_epoch = utc_tai_offset(Clock::epoch());
    auto leap_delta = utc_tai_offset(utc) - leap_epoch;
    return Clock::at(utc + leap_delta);
}

boost::optional<std::chrono::hours> parse_duration_hours(const std::string& s)
{
    if (s.size() < 2) {
        return boost::none; // need at least one digit + unit
    }
    char unit = s.back();
    const char* first = s.data();
    const char* last = s.data() + s.size() - 1; // up to (excluding) the unit
    long n = 0;
    auto [ptr, ec] = std::from_chars(first, last, n);
    if (ec != std::errc {} || ptr != last || n < 0) {
        return boost::none;
    }
    switch (unit) {
        case 'h':
            return std::chrono::hours(n);
        case 'd':
            if (n > std::chrono::hours::max().count() / 24) {
                return boost::none;
            }
            return std::chrono::hours(n * 24);
        case 'w':
            if (n > std::chrono::hours::max().count() / (24 * 7)) {
                return boost::none;
            }
            return std::chrono::hours(n * 24 * 7);
        case 'm':
            return std::chrono::duration_cast<std::chrono::hours>(std::chrono::minutes(n));
        case 's':
            return std::chrono::duration_cast<std::chrono::hours>(std::chrono::seconds(n));
        default:
            return boost::none;
    }
}

boost::optional<Clock::time_point> parse_validity_start(const std::string& s)
{
    if (s.empty()) {
        return boost::none;
    }
    if (s.front() == '+') {
        auto duration = parse_duration_hours(s.substr(1));
        if (!duration) {
            return boost::none;
        }
        return current_time() + *duration;
    }
    // Absolute date: "YYYY-MM-DDTHH:MM:SS", "YYYY-MM-DD HH:MM:SS", or "YYYY-MM-DD" (00:00:00 implied)
    std::string normalised = s;
    auto t_pos = normalised.find('T');
    if (t_pos != std::string::npos) {
        normalised[t_pos] = ' ';
    }
    boost::posix_time::ptime pt;
    try {
        if (normalised.find(' ') == std::string::npos) {
            pt = boost::posix_time::time_from_string(normalised + " 00:00:00");
        } else {
            pt = boost::posix_time::time_from_string(normalised);
        }
    } catch (...) {
        // keep our public API non-throwing
        return boost::none;
    }
    if (pt.is_special()) {
        return boost::none;
    }
    return Clock::at(pt);
}

} // namespace pki
} // namespace vanetza
