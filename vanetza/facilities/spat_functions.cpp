#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/bit_string.hpp>
#include <vanetza/asn1/its/SPAT.h>
#include <vanetza/asn1/its/IntersectionState.h>
#include <vanetza/asn1/its/MovementEvent.h>
#include <vanetza/asn1/its/MovementState.h>
#include <vanetza/asn1/its/TimeChangeDetails.h>
#include <vanetza/facilities/spat_functions.hpp>
#include <vanetza/asn1/its/asn_constant.h>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <array>
#include <stdexcept>

namespace vanetza
{
namespace facilities
{

const std::chrono::minutes cMinuteOfTheYearUnknown { max_val_MinuteOfTheYear };
// TimeMark values given by C2C-CC RS 2077 (parameter settings) as well:
// pTimeMarkOutOfRange 36000 and pTimeMarkUnknown 36001
const TimeMark cTimeMarkOutOfRange { max_val_TimeMark - 1 };
const TimeMark cTimeMarkUnknown { max_val_TimeMark };
const long cMsgCountMax = max_val_MsgCount;

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

namespace
{

// round up to tenths of a second, Clock's epoch starts at a full second
Clock::time_point ceil_to_tenth(const Clock::time_point& at)
{
    const Clock::duration excess = at.time_since_epoch() % TimeMark(1);
    return excess == Clock::duration::zero() ? at : at - excess + TimeMark(1);
}

Clock::time_point minute_begin(const Clock::time_point& at)
{
    return at - dsecond(at) - at.time_since_epoch() % std::chrono::milliseconds(1);
}

} // namespace

long msg_count(long counter) noexcept
{
    long count = counter % (cMsgCountMax + 1);
    if (count < 0) {
        count += cMsgCountMax + 1;
    }
    return count;
}

IntersectionState& add_intersection_state(SPAT& spat, unsigned id, unsigned revision)
{
    auto intersection = asn1::make_unique<IntersectionState_t>(asn_DEF_IntersectionState);
    intersection->id.id = id;
    intersection->revision = revision;
    // IntersectionStatusObject ::= BIT STRING (SIZE(16)), no flag set
    asn1::allocate_bits(intersection->status, 16);
    return asn1::append(spat.intersections, std::move(intersection));
}

void set_timestamp(IntersectionState& intersection, const Clock::time_point& at)
{
    asn1::allocate_optional(intersection.moy) = static_cast<long>(minute_of_the_year(at).count());
    asn1::allocate_optional(intersection.timeStamp) = static_cast<long>(dsecond(at).count());
}

MovementState& add_movement(IntersectionState& intersection, unsigned signal_group)
{
    auto movement = asn1::make_unique<MovementState_t>(asn_DEF_MovementState);
    movement->signalGroup = signal_group;
    return asn1::append(intersection.states, std::move(movement));
}

MovementEvent& add_event(MovementState& movement, long phase_state)
{
    auto event = asn1::make_unique<MovementEvent_t>(asn_DEF_MovementEvent);
    event->eventState = phase_state;
    return asn1::append(movement.state_time_speed, std::move(event));
}

void set_timing(MovementEvent& event, const MovementTiming& timing, const Clock::time_point& timestamp)
{
    TimingError error = TimingError::Ok;
    set_timing(event, timing, timestamp, error);

    switch (error) {
    case TimingError::Ok:
        return;
    case TimingError::MinEndBeforeMinute:
        throw std::invalid_argument("minimum end time before the minute of the timestamp");
    case TimingError::LikelyWithoutConfidence:
        throw std::invalid_argument("likely time without confidence");
    case TimingError::OutOfMemory:
        throw asn1::asn1c_exception(asn1::asn1c_error(asn1::ErrorCode::OutOfMemory));
    }
}

void set_timing(MovementEvent& event, const MovementTiming& timing, const Clock::time_point& timestamp,
    TimingError& error) noexcept
{
    const Clock::time_point window_begin = minute_begin(timestamp);
    const Clock::time_point window_end = window_begin + std::chrono::hours(1);
    const auto representable = [&](const Clock::time_point& t) { return t >= window_begin && t < window_end; };
    if (timing.min_end < window_begin) {
        error = TimingError::MinEndBeforeMinute;
        return;
    }
    if (timing.likely && !timing.confidence) {
        error = TimingError::LikelyWithoutConfidence;
        return;
    }

    try {
        auto details = asn1::make_unique<TimeChangeDetails_t>(asn_DEF_TimeChangeDetails);
        details->minEndTime = timing.min_end < window_end ? time_mark(timing.min_end).count() : cTimeMarkOutOfRange.count();
        if (timing.start && representable(*timing.start)) {
            asn1::allocate_optional(details->startTime) = time_mark(*timing.start).count();
        }
        if (timing.max_end && representable(ceil_to_tenth(*timing.max_end))) {
            asn1::allocate_optional(details->maxEndTime) = time_mark(ceil_to_tenth(*timing.max_end)).count();
        }
        if (timing.likely && representable(*timing.likely)) {
            asn1::allocate_optional(details->likelyTime) = time_mark(*timing.likely).count();
            if (timing.confidence) {
                asn1::allocate_optional(details->confidence) = *timing.confidence;
            }
        }
        if (timing.next && representable(*timing.next)) {
            asn1::allocate_optional(details->nextTime) = time_mark(*timing.next).count();
        }

        // the event is only modified once the new timing is complete
        ASN_STRUCT_FREE(asn_DEF_TimeChangeDetails, event.timing);
        event.timing = details.release();
    } catch (...) {
        // only memory allocation can fail here
        error = TimingError::OutOfMemory;
        return;
    }
    error = TimingError::Ok;
}

} // namespace facilities
} // namespace vanetza
