#ifndef SPAT_FUNCTIONS_HPP_K3VQ8ZRT
#define SPAT_FUNCTIONS_HPP_K3VQ8ZRT

#include <vanetza/common/clock.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace facilities
{

/**
 * Time conversions for SPATEM and MAPEM (ETSI TS 103 301, ISO TS 19091 DSRC data elements).
 *
 * MinuteOfTheYear, DSecond and TimeMark refer to UTC. All functions taking a time point
 * expect a UTC based time point, i.e. Clock::at(utc_date_time) as produced by a runtime
 * driven by UTC (e.g. socktap's TimeTrigger). A time point derived from TAI, e.g. from GNSS
 * time like Vanetza's GPS position provider does, has to be converted by utc_from_tai() first.
 * Leap seconds are not represented by Clock, hence leap second codes are never produced.
 */

/** MinuteOfTheYear value indicating an invalid or unknown minute */
extern const long cMinuteOfTheYearUnknown;

/**
 * TimeMark value 36000: a leap second in ISO TS 19091, used for times more than
 * one hour ahead by C2C-CC RS 2077 (pTimeMarkOutOfRange)
 */
extern const long cTimeMarkOutOfRange;

/** TimeMark value indicating an unknown time */
extern const long cTimeMarkUnknown;

/**
 * Convert a TAI based time point to a UTC based time point
 * \param tai time point whose Clock::at() yields the TAI date and time
 * \return time point whose Clock::at() yields the UTC date and time
 */
Clock::time_point utc_from_tai(const Clock::time_point& tai);

/**
 * Get minutes elapsed since begin of the UTC year
 * \param at time point
 * \return MinuteOfTheYear value (0..527039)
 */
long minute_of_the_year(const Clock::time_point& at);

/**
 * Get milliseconds elapsed since begin of the UTC minute
 * \param at time point
 * \return DSecond value (0..59999)
 */
long dsecond(const Clock::time_point& at);

/**
 * Get tenths of a second elapsed since begin of the UTC hour (truncated)
 * \param at time point
 * \return TimeMark value (0..35999)
 */
long time_mark(const Clock::time_point& at);

/**
 * Resolve a TimeMark to an absolute time point
 *
 * A TimeMark only identifies a position within an hour. It refers to the hour of the
 * reference time, or to the following hour if it is earlier than the begin of the
 * reference minute (C2C-CC RS 2077, RS_ARSM_54). Hence time points more than one minute
 * in the past cannot be represented, which matters for startTime only.
 *
 * \param mark TimeMark value
 * \param reference time of the message, e.g. derived from moy and timeStamp
 * \return time point or none if mark is unknown, a leap second or out of range
 */
boost::optional<Clock::time_point> time_mark_to_time_point(long mark, const Clock::time_point& reference);

} // namespace facilities
} // namespace vanetza

#endif /* SPAT_FUNCTIONS_HPP_K3VQ8ZRT */
