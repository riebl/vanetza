#pragma once

#include <vanetza/common/clock.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/optional/optional.hpp>
#include <chrono>
#include <string>

namespace vanetza
{
namespace pki
{

/**
 * Get TAI offset relative to UTC for a particular time point t
 * \param t offset at this time point
 * \return TAI offset in seconds
 */
boost::posix_time::time_duration utc_tai_offset(boost::posix_time::ptime t);

/**
 * Get current time from system clock, corrected by TAI offset
 */
Clock::time_point current_time();

/**
 * Parse a human-readable duration into whole hours.
 *
 * Accepted form: "<N><unit>" where N is a non-negative integer and unit is
 * one of:
 *   s — seconds (truncated to whole hours)
 *   m — minutes (truncated to whole hours)
 *   h — hours
 *   d — days   (24 h)
 *   w — weeks  (168 h)
 *
 * Returns boost::none on empty input, missing/unknown unit, negative value,
 * unparseable number, or trailing garbage.
 */
boost::optional<std::chrono::hours> parse_duration_hours(const std::string&);

/**
 * Parse a validity-start specification.
 *
 * Two accepted forms:
 *   - Relative: "+<N><unit>" — interpreted as `current_time() + duration`,
 *     where the duration follows the same grammar as parse_duration_hours().
 *   - Absolute (UTC): an ISO-extended date "YYYY-MM-DD" (00:00:00 implied),
 *     or a date+time "YYYY-MM-DDTHH:MM:SS" / "YYYY-MM-DD HH:MM:SS".
 *
 * Returns boost::none on empty input, malformed date, or unrecognised
 * relative duration.
 */
boost::optional<Clock::time_point> parse_validity_start(const std::string&);

} // namespace pki
} // namespace vanetza
