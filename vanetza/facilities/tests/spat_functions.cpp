#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/TimeChangeDetails.h>
#include <vanetza/asn1/spatem.hpp>
#include <vanetza/facilities/spat_functions.hpp>
#include <limits>
#include <stdexcept>
#include <utility>

using namespace vanetza;
using namespace vanetza::facilities;
using std::chrono::minutes;
using std::chrono::milliseconds;

TEST(SpatFunctions, minute_of_the_year)
{
    EXPECT_EQ(minutes(0), minute_of_the_year(Clock::at("2026-01-01 00:00:00")));
    EXPECT_EQ(minutes(0), minute_of_the_year(Clock::at("2026-01-01 00:00:59.999")));
    EXPECT_EQ(minutes(1), minute_of_the_year(Clock::at("2026-01-01 00:01:00")));
    EXPECT_EQ(minutes(525599), minute_of_the_year(Clock::at("2026-12-31 23:59:30")));
    // leap year has one more day
    EXPECT_EQ(minutes(527039), minute_of_the_year(Clock::at("2024-12-31 23:59:00")));
    EXPECT_LT(minute_of_the_year(Clock::at("2024-12-31 23:59:59.999")), cMinuteOfTheYearUnknown);
}

TEST(SpatFunctions, dsecond)
{
    EXPECT_EQ(milliseconds(0), dsecond(Clock::at("2026-10-03 10:15:00")));
    EXPECT_EQ(milliseconds(30250), dsecond(Clock::at("2026-10-03 10:15:30.250")));
    EXPECT_EQ(milliseconds(59999), dsecond(Clock::at("2026-10-03 10:15:59.999")));
}

TEST(SpatFunctions, time_mark)
{
    EXPECT_EQ(TimeMark(0), time_mark(Clock::at("2026-10-03 10:00:00")));
    // 15 min 30.25 s -> 9302.5 tenths, truncated
    EXPECT_EQ(TimeMark(9302), time_mark(Clock::at("2026-10-03 10:15:30.250")));
    EXPECT_EQ(TimeMark(35999), time_mark(Clock::at("2026-10-03 10:59:59.999")));
}

TEST(SpatFunctions, time_mark_roundtrip)
{
    const auto at = Clock::at("2026-10-03 10:15:30.200");
    auto resolved = time_mark_to_time_point(time_mark(at), at);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(at, *resolved);
}

TEST(SpatFunctions, time_mark_next_hour)
{
    // forecast 20 s ahead crosses the hour boundary
    const auto now = Clock::at("2026-10-03 10:59:50");
    auto resolved = time_mark_to_time_point(TimeMark(100), now);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:00:10"), *resolved);
}

TEST(SpatFunctions, time_mark_hour_rule)
{
    // C2C-CC RS 2077, RS_ARSM_54: a mark refers to the hour of the reference time,
    // or to the following hour if it is earlier than the begin of the reference minute
    const auto now = Clock::at("2026-10-03 11:00:05");
    auto resolved = time_mark_to_time_point(TimeMark(35950), now);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:59:55"), *resolved);

    // same minute: an earlier mark still belongs to the current hour
    const auto later = Clock::at("2026-10-03 10:15:40");
    resolved = time_mark_to_time_point(TimeMark(9001), later); // xx:15:00.1
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:15:00.100"), *resolved);

    // before the reference minute: following hour
    resolved = time_mark_to_time_point(TimeMark(8999), later); // xx:14:59.9
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:14:59.900"), *resolved);
}

TEST(SpatFunctions, time_mark_special_values)
{
    const auto now = Clock::at("2026-10-03 10:00:00");
    EXPECT_FALSE(time_mark_to_time_point(cTimeMarkUnknown, now));
    EXPECT_FALSE(time_mark_to_time_point(cTimeMarkOutOfRange, now));
    EXPECT_FALSE(time_mark_to_time_point(TimeMark(-1), now));
}

TEST(SpatFunctions, utc_from_tai)
{
    // TAI - UTC: 32 s in 2005, 37 s since 2017
    EXPECT_EQ(Clock::at("2005-06-01 12:00:00"), utc_from_tai(Clock::at("2005-06-01 12:00:32")));
    EXPECT_EQ(Clock::at("2026-10-03 10:00:00"), utc_from_tai(Clock::at("2026-10-03 10:00:37")));
    // first instant after the leap second inserted at the end of 2016
    EXPECT_EQ(Clock::at("2017-01-01 00:00:00"), utc_from_tai(Clock::at("2017-01-01 00:00:37")));
    EXPECT_EQ(Clock::at("2016-12-31 23:59:59"), utc_from_tai(Clock::at("2017-01-01 00:00:35")));
}

TEST(SpatFunctions, time_mark_at_hour_edges)
{
    // minute 0 of the hour: every mark belongs to the current hour
    const auto first_minute = Clock::at("2026-10-03 10:00:30");
    auto resolved = time_mark_to_time_point(TimeMark(0), first_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:00:00"), *resolved);

    // minute 59: only marks of the last minute stay in the current hour
    const auto last_minute = Clock::at("2026-10-03 10:59:30");
    resolved = time_mark_to_time_point(TimeMark(35400), last_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 10:59:00"), *resolved);
    resolved = time_mark_to_time_point(TimeMark(35399), last_minute);
    ASSERT_TRUE(resolved);
    EXPECT_EQ(Clock::at("2026-10-03 11:58:59.900"), *resolved);
}

TEST(SpatFunctions, special_values)
{
    // C2C-CC RS 2077 parameter settings: pTimeMarkOutOfRange and pTimeMarkUnknown
    EXPECT_EQ(36000, cTimeMarkOutOfRange.count());
    EXPECT_EQ(36001, cTimeMarkUnknown.count());
    EXPECT_EQ(527040, cMinuteOfTheYearUnknown.count());
}

TEST(SpatFunctions, next_msg_count)
{
    EXPECT_EQ(1, next_msg_count(0));
    EXPECT_EQ(127, next_msg_count(126));
    EXPECT_EQ(0, next_msg_count(cMsgCountMax));
    // any input is taken modulo cMsgCountMax + 1
    EXPECT_EQ(1, next_msg_count(128));
    EXPECT_EQ(0, next_msg_count(255));
    EXPECT_EQ(0, next_msg_count(-1));
    EXPECT_EQ(127, next_msg_count(-2));

    // extreme values neither overflow nor produce an unencodable MsgCount
    const long extremes[] = { std::numeric_limits<long>::min(), std::numeric_limits<long>::max() };
    for (long extreme : extremes) {
        EXPECT_GE(next_msg_count(extreme), 0);
        EXPECT_LE(next_msg_count(extreme), cMsgCountMax);
        EXPECT_EQ((msg_count(extreme) + 1) % (cMsgCountMax + 1), next_msg_count(extreme));
    }
}

TEST(SpatFunctions, msg_count)
{
    EXPECT_EQ(0, msg_count(0));
    EXPECT_EQ(127, msg_count(127));
    EXPECT_EQ(0, msg_count(128));
    EXPECT_EQ(1, msg_count(129));
    EXPECT_EQ(126, msg_count(-2));
    EXPECT_EQ(127, msg_count(-1));
    EXPECT_EQ(0, msg_count(-128));

    // consecutive counters give consecutive MsgCounts, wrapping around
    for (long counter = 0; counter <= 128; ++counter) {
        EXPECT_EQ(counter % (cMsgCountMax + 1), msg_count(counter));
    }

    const long extremes[] = { std::numeric_limits<long>::min(), std::numeric_limits<long>::max() };
    for (long extreme : extremes) {
        EXPECT_GE(msg_count(extreme), 0);
        EXPECT_LE(msg_count(extreme), cMsgCountMax);
    }
}

TEST(SpatFunctions, build_spatem)
{
    const auto now = Clock::at("2026-10-03 10:15:30.250");

    asn1::Spatem spatem;
    spatem->header.protocolVersion = 2;
    spatem->header.messageID = ItsPduHeader__messageID_spatem;
    spatem->header.stationID = 1337;

    IntersectionState& intersection = add_intersection_state(spatem->spat, 42, next_msg_count(cMsgCountMax));
    set_timestamp(intersection, now);
    MovementState& movement = add_movement(intersection, 3);
    MovementEvent& event = add_event(movement, MovementPhaseState_protected_Movement_Allowed);

    MovementTiming timing;
    timing.start = now - std::chrono::seconds(10);
    timing.min_end = now + std::chrono::milliseconds(5050);
    timing.max_end = now + std::chrono::milliseconds(20040);
    timing.likely = now + std::chrono::seconds(12);
    timing.confidence = 12;
    set_timing(event, timing, now);

    std::string error;
    ASSERT_TRUE(spatem.validate(error)) << error;
    asn1::Spatem decoded;
    ASSERT_TRUE(decoded.decode(spatem.encode()));

    const IntersectionState_t* rx = decoded->spat.intersections.list.array[0];
    EXPECT_EQ(42, rx->id.id);
    EXPECT_EQ(0, rx->revision);
    ASSERT_NE(nullptr, rx->moy);
    EXPECT_EQ(minute_of_the_year(now).count(), *rx->moy);
    ASSERT_NE(nullptr, rx->timeStamp);
    EXPECT_EQ(30250, *rx->timeStamp);

    const MovementEvent_t* rx_event = rx->states.list.array[0]->state_time_speed.list.array[0];
    EXPECT_EQ(3, rx->states.list.array[0]->signalGroup);
    EXPECT_EQ(MovementPhaseState_protected_Movement_Allowed, rx_event->eventState);
    ASSERT_NE(nullptr, rx_event->timing);
    // 10:15:20.250 -> 9202, 10:15:35.300 -> 9353 (truncated)
    ASSERT_NE(nullptr, rx_event->timing->startTime);
    EXPECT_EQ(9202, *rx_event->timing->startTime);
    EXPECT_EQ(9353, rx_event->timing->minEndTime);
    // 10:15:50.290 -> 9503 (rounded up, truncation would give 9502)
    ASSERT_NE(nullptr, rx_event->timing->maxEndTime);
    EXPECT_EQ(9503, *rx_event->timing->maxEndTime);
    ASSERT_NE(nullptr, rx_event->timing->likelyTime);
    EXPECT_EQ(9422, *rx_event->timing->likelyTime);
    ASSERT_NE(nullptr, rx_event->timing->confidence);
    EXPECT_EQ(12, *rx_event->timing->confidence);
    EXPECT_EQ(nullptr, rx_event->timing->nextTime);
}

TEST(SpatFunctions, max_end_rounding_at_hour_end)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    MovementTiming timing;
    timing.min_end = Clock::at("2026-10-03 10:59:59.950");
    timing.max_end = Clock::at("2026-10-03 10:59:59.950");
    set_timing(event, timing, Clock::at("2026-10-03 10:59:59.900"));

    EXPECT_EQ(35999, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(0, *event.timing->maxEndTime); // first tenth of next hour
}

TEST(SpatFunctions, max_end_rounds_up_sub_millisecond_excess)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    MovementTiming timing;
    timing.min_end = Clock::at("2026-10-03 10:00:00.100") + std::chrono::microseconds(1);
    timing.max_end = timing.min_end;
    set_timing(event, timing, Clock::at("2026-10-03 10:00:00.000"));

    EXPECT_EQ(1, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(2, *event.timing->maxEndTime);
}

TEST(SpatFunctions, timing_beyond_one_hour)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    // TimeMarks resolve from 12:00:00 to 12:59:59.900
    const auto now = Clock::at("2026-10-04 12:00:30.000");
    MovementTiming timing;
    timing.start = Clock::at("2026-10-04 11:59:59.900");
    timing.min_end = Clock::at("2026-10-05 07:00:00.000");
    timing.max_end = Clock::at("2026-10-04 13:00:00.000");
    timing.likely = Clock::at("2026-10-04 13:00:00.000");
    timing.confidence = 15;
    timing.next = Clock::at("2026-10-04 13:00:00.000");
    set_timing(event, timing, now);

    ASSERT_NE(nullptr, event.timing);
    EXPECT_EQ(cTimeMarkOutOfRange.count(), event.timing->minEndTime);
    EXPECT_EQ(nullptr, event.timing->startTime);
    EXPECT_EQ(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(nullptr, event.timing->likelyTime);
    EXPECT_EQ(nullptr, event.timing->confidence);
    EXPECT_EQ(nullptr, event.timing->nextTime);

    timing.start = Clock::at("2026-10-04 12:00:00.000");
    timing.min_end = Clock::at("2026-10-04 12:59:59.900");
    timing.max_end = Clock::at("2026-10-04 12:59:59.850"); // rounded up to the last tenth
    timing.likely = timing.min_end;
    timing.next = timing.min_end;
    set_timing(event, timing, now);

    EXPECT_EQ(35999, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->startTime);
    EXPECT_EQ(0, *event.timing->startTime);
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(35999, *event.timing->maxEndTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    ASSERT_NE(nullptr, event.timing->confidence);
    ASSERT_NE(nullptr, event.timing->nextTime);
    EXPECT_EQ(35999, *event.timing->nextTime);
}

TEST(SpatFunctions, timing_at_window_edges)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    // TimeMarks resolve from 12:00:00 to 12:59:59.900
    const auto now = Clock::at("2026-10-04 12:00:30.000");
    MovementTiming timing;
    timing.min_end = Clock::at("2026-10-04 12:00:00.000");
    timing.max_end = Clock::at("2026-10-04 12:59:59.950"); // rounded up to 13:00:00
    set_timing(event, timing, now);

    ASSERT_NE(nullptr, event.timing);
    EXPECT_EQ(0, event.timing->minEndTime);
    EXPECT_EQ(nullptr, event.timing->maxEndTime);

    // 13:00:00 would give TimeMark 0 again
    timing.min_end = Clock::at("2026-10-04 13:00:00.000");
    timing.max_end = boost::none;
    set_timing(event, timing, now);

    EXPECT_EQ(cTimeMarkOutOfRange.count(), event.timing->minEndTime);
}

TEST(SpatFunctions, set_timing_replaces_previous_timing)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:00:00.000");
    MovementTiming timing;
    timing.start = now;
    timing.min_end = now + std::chrono::seconds(5);
    timing.max_end = now + std::chrono::seconds(6);
    timing.likely = now + std::chrono::seconds(5);
    timing.confidence = 15;
    timing.next = now + std::chrono::seconds(30);
    set_timing(event, timing, now);

    MovementTiming uncertain;
    uncertain.min_end = now + std::chrono::seconds(2);
    set_timing(event, uncertain, now);

    ASSERT_NE(nullptr, event.timing);
    EXPECT_EQ(20, event.timing->minEndTime);
    EXPECT_EQ(nullptr, event.timing->startTime);
    EXPECT_EQ(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(nullptr, event.timing->likelyTime);
    EXPECT_EQ(nullptr, event.timing->confidence);
    EXPECT_EQ(nullptr, event.timing->nextTime);
}

TEST(SpatFunctions, min_end_before_timestamp_minute_is_rejected)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    MovementTiming timing;
    timing.min_end = Clock::at("2026-10-03 10:14:59.900");
    EXPECT_THROW(set_timing(event, timing, Clock::at("2026-10-03 10:15:00.000")), std::invalid_argument);
}

TEST(SpatFunctions, likely_time_requires_confidence)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:15:00.000");
    MovementTiming timing;
    timing.min_end = now + std::chrono::seconds(5);
    timing.max_end = now + std::chrono::seconds(10);
    timing.likely = now + std::chrono::seconds(7);
    EXPECT_THROW(set_timing(event, timing, now), std::invalid_argument); // C2C-CC RS 2077 RS_ARSM_115

    timing.confidence = 12;
    set_timing(event, timing, now);
    ASSERT_NE(nullptr, event.timing);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    ASSERT_NE(nullptr, event.timing->confidence);
    EXPECT_EQ(12, *event.timing->confidence);
}

TEST(SpatFunctions, confidence_without_likely_time_is_omitted)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:15:00.000");
    MovementTiming timing;
    timing.min_end = now + std::chrono::seconds(5);
    timing.confidence = 12;
    set_timing(event, timing, now);

    ASSERT_NE(nullptr, event.timing);
    EXPECT_EQ(nullptr, event.timing->likelyTime);
    EXPECT_EQ(nullptr, event.timing->confidence);
}

TEST(SpatFunctions, set_timing_without_exceptions)
{
    static_assert(noexcept(set_timing(std::declval<MovementEvent&>(), std::declval<const MovementTiming&>(),
        std::declval<const Clock::time_point&>(), std::declval<TimingError&>())),
        "non-throwing set_timing overload is expected");

    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:15:30.250");
    MovementTiming timing;
    timing.start = now - std::chrono::seconds(10);
    timing.min_end = now + std::chrono::milliseconds(5050);
    timing.max_end = now + std::chrono::milliseconds(20040);
    timing.likely = now + std::chrono::seconds(12);
    timing.confidence = 12;

    TimingError error = TimingError::OutOfMemory;
    set_timing(event, timing, now, error);

    EXPECT_EQ(TimingError::Ok, error);
    ASSERT_NE(nullptr, event.timing);
    // 10:15:20.250 -> 9202, 10:15:35.300 -> 9353 (truncated)
    ASSERT_NE(nullptr, event.timing->startTime);
    EXPECT_EQ(9202, *event.timing->startTime);
    EXPECT_EQ(9353, event.timing->minEndTime);
    // 10:15:50.290 -> 9503 (rounded up, truncation would give 9502)
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(9503, *event.timing->maxEndTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    EXPECT_EQ(9422, *event.timing->likelyTime);
    ASSERT_NE(nullptr, event.timing->confidence);
    EXPECT_EQ(12, *event.timing->confidence);
    EXPECT_EQ(nullptr, event.timing->nextTime);

    // both overloads produce the same timing
    MovementEvent& throwing_event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 1), 1),
        MovementPhaseState_stop_And_Remain);
    set_timing(throwing_event, timing, now);
    ASSERT_NE(nullptr, throwing_event.timing);
    EXPECT_EQ(0, asn1::compare(asn_DEF_TimeChangeDetails, event.timing, throwing_event.timing));
}

TEST(SpatFunctions, set_timing_error_codes)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:15:00.000");
    MovementTiming valid;
    valid.start = now;
    valid.min_end = now + std::chrono::seconds(5);
    valid.max_end = now + std::chrono::seconds(10);
    valid.likely = now + std::chrono::seconds(7);
    valid.confidence = 12;
    TimingError error = TimingError::OutOfMemory;
    set_timing(event, valid, now, error);
    ASSERT_EQ(TimingError::Ok, error);
    ASSERT_NE(nullptr, event.timing);
    const TimeChangeDetails_t* previous = event.timing;

    MovementTiming min_end_before_minute;
    min_end_before_minute.min_end = Clock::at("2026-10-03 10:14:59.900");
    set_timing(event, min_end_before_minute, now, error);
    EXPECT_EQ(TimingError::MinEndBeforeMinute, error);
    EXPECT_EQ(previous, event.timing);
    EXPECT_EQ(9050, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->startTime);
    EXPECT_EQ(9000, *event.timing->startTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    EXPECT_EQ(9070, *event.timing->likelyTime);
    ASSERT_NE(nullptr, event.timing->confidence);
    EXPECT_EQ(12, *event.timing->confidence);

    MovementTiming likely_without_confidence;
    likely_without_confidence.min_end = now + std::chrono::seconds(5);
    likely_without_confidence.likely = now + std::chrono::seconds(7);
    set_timing(event, likely_without_confidence, now, error);
    EXPECT_EQ(TimingError::LikelyWithoutConfidence, error);
    EXPECT_EQ(previous, event.timing);
    EXPECT_EQ(9050, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(9100, *event.timing->maxEndTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    EXPECT_EQ(9070, *event.timing->likelyTime);
}

TEST(SpatFunctions, set_timing_exception_keeps_event)
{
    asn1::Spatem spatem;
    MovementEvent& event = add_event(add_movement(add_intersection_state(spatem->spat, 1, 0), 1),
        MovementPhaseState_stop_And_Remain);

    const auto now = Clock::at("2026-10-03 10:15:00.000");
    MovementTiming valid;
    valid.min_end = now + std::chrono::seconds(5);
    valid.max_end = now + std::chrono::seconds(10);
    valid.likely = now + std::chrono::seconds(7);
    valid.confidence = 12;
    set_timing(event, valid, now);
    ASSERT_NE(nullptr, event.timing);
    const TimeChangeDetails_t* previous = event.timing;

    MovementTiming min_end_before_minute;
    min_end_before_minute.min_end = Clock::at("2026-10-03 10:14:59.900");
    EXPECT_THROW(set_timing(event, min_end_before_minute, now), std::invalid_argument);
    EXPECT_EQ(previous, event.timing);
    EXPECT_EQ(9050, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->maxEndTime);
    EXPECT_EQ(9100, *event.timing->maxEndTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    EXPECT_EQ(9070, *event.timing->likelyTime);
    ASSERT_NE(nullptr, event.timing->confidence);
    EXPECT_EQ(12, *event.timing->confidence);

    MovementTiming likely_without_confidence;
    likely_without_confidence.min_end = now + std::chrono::seconds(5);
    likely_without_confidence.likely = now + std::chrono::seconds(7);
    EXPECT_THROW(set_timing(event, likely_without_confidence, now), std::invalid_argument);
    EXPECT_EQ(previous, event.timing);
    EXPECT_EQ(9050, event.timing->minEndTime);
    ASSERT_NE(nullptr, event.timing->likelyTime);
    EXPECT_EQ(9070, *event.timing->likelyTime);
}
