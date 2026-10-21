#ifndef SPAT_FUNCTIONS_HPP_K3VQ8ZRT
#define SPAT_FUNCTIONS_HPP_K3VQ8ZRT

#include <vanetza/common/clock.hpp>
#include <boost/optional/optional.hpp>
#include <chrono>
#include <cstdint>
#include <ratio>

// forward declaration of asn1c generated struct
struct IntersectionState;
struct MovementEvent;
struct MovementState;
struct SPAT;

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

/** Tenths of a second elapsed since begin of the UTC hour (TimeMark data element) */
using TimeMark = std::chrono::duration<int32_t, std::ratio<1, 10>>;

/** MinuteOfTheYear value indicating an invalid or unknown minute */
extern const std::chrono::minutes cMinuteOfTheYearUnknown;

/**
 * TimeMark value 36000: a leap second in ISO TS 19091, used for times more than
 * one hour ahead by C2C-CC RS 2077 (pTimeMarkOutOfRange)
 */
extern const TimeMark cTimeMarkOutOfRange;

/** TimeMark value indicating an unknown time (pTimeMarkUnknown in C2C-CC RS 2077) */
extern const TimeMark cTimeMarkUnknown;

/**
 * Convert a TAI based time point to a UTC based time point
 * \param tai time point whose Clock::at() yields the TAI date and time
 * \return time point whose Clock::at() yields the UTC date and time
 */
Clock::time_point utc_from_tai(const Clock::time_point& tai);

/**
 * Get minutes elapsed since begin of the UTC year
 * \param at time point
 * \return MinuteOfTheYear value (0..527039 minutes)
 */
std::chrono::minutes minute_of_the_year(const Clock::time_point& at);

/**
 * Get milliseconds elapsed since begin of the UTC minute
 * \param at time point
 * \return DSecond value (0..59999 milliseconds)
 */
std::chrono::milliseconds dsecond(const Clock::time_point& at);

/**
 * Get tenths of a second elapsed since begin of the UTC hour (truncated)
 * \param at time point
 * \return TimeMark value (0..35999 tenths of a second)
 */
TimeMark time_mark(const Clock::time_point& at);

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
boost::optional<Clock::time_point> time_mark_to_time_point(TimeMark mark, const Clock::time_point& reference);

/** Largest MsgCount value before wrap-around */
extern const long cMsgCountMax;

/**
 * Get MsgCount following the given one, wrapping around after cMsgCountMax
 * \param count current MsgCount value (0..127)
 * \return next MsgCount value (0..127)
 */
long next_msg_count(long count);

/**
 * Timing of a movement event as absolute time points (ISO TS 19091 TimeChangeDetails)
 */
struct MovementTiming
{
    boost::optional<Clock::time_point> start; /**< begin of this state */
    Clock::time_point min_end; /**< earliest end of this state */
    boost::optional<Clock::time_point> max_end; /**< latest end of this state */
    boost::optional<Clock::time_point> likely; /**< most likely end of this state */
    boost::optional<long> confidence; /**< TimeIntervalConfidence of likely end (0..15) */
    boost::optional<Clock::time_point> next; /**< next start of the allowed movement */
};

/**
 * Append an intersection state to SPAT
 * \param spat SPAT container (destination)
 * \param id intersection identifier unique within its road regulator (0..65535)
 * \param revision MsgCount of the intersection configuration (0..127)
 * \return appended intersection state, owned by spat
 */
IntersectionState& add_intersection_state(SPAT& spat, long id, long revision);

/**
 * Set moy and timeStamp of an intersection state
 * \param intersection intersection state (destination)
 * \param at time point of the state
 */
void set_timestamp(IntersectionState& intersection, const Clock::time_point& at);

/**
 * Append a movement (signal group) state to an intersection state
 * \param intersection intersection state (destination)
 * \param signal_group signal group identifier (0..255)
 * \return appended movement state, owned by intersection
 */
MovementState& add_movement(IntersectionState& intersection, long signal_group);

/**
 * Append a movement event to a movement state
 * \param movement movement state (destination)
 * \param phase_state MovementPhaseState value
 * \return appended movement event, owned by movement
 */
MovementEvent& add_event(MovementState& movement, long phase_state);

/**
 * Set timing of a movement event, replacing any previous timing
 *
 * Lower bounds (start, min_end) are truncated and upper bounds (max_end) rounded up
 * to tenths of a second, so the encoded interval always contains the given one.
 *
 * A TimeMark is unambiguous only from the begin of the timestamp's minute for one hour
 * (C2C-CC RS 2077 RS_ARSM_54). A minimum end time beyond is encoded as cTimeMarkOutOfRange,
 * the optional times outside are omitted (confidence together with the likely time).
 * A likely time requires its confidence (RS_ARSM_115).
 *
 * \param event movement event (destination)
 * \param timing absolute timing
 * \param timestamp time of the intersection state, see set_timestamp()
 * \throw std::invalid_argument if the minimum end time lies before the timestamp's minute
 * or a likely time comes without confidence
 */
void set_timing(MovementEvent& event, const MovementTiming& timing, const Clock::time_point& timestamp);

} // namespace facilities
} // namespace vanetza

#endif /* SPAT_FUNCTIONS_HPP_K3VQ8ZRT */
