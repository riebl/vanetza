#pragma once
#include <vanetza/facilities/path_history.hpp>
#include <vanetza/facilities/path_point.hpp>
#include <vanetza/facilities/utils.hpp>
#include <chrono>
#include <type_traits>

namespace vanetza
{
namespace facilities
{

// C2C-CC BSP CAM trace limits (RS_BSP_318)
static const units::Length cCamTraceMinLength = 200.0 * units::si::meter;
static constexpr std::size_t cCamTraceMaxPoints = 23;

template<typename SomePathSequence, typename SomePathPoint>
void copy(const facilities::PathHistory& src, SomePathSequence& dest,
        units::Length min_distance = cCamTraceMinLength, std::size_t max_points = cCamTraceMaxPoints)
{
    using SomePathDeltaTime = typename std::remove_pointer<decltype(SomePathPoint::pathDeltaTime)>::type;

    static const auto scDeltaTimeStepLength = boost::posix_time::milliseconds(10);
    static const auto scMaxDeltaTime = scDeltaTimeStepLength * 65535;

    // ETSI TS 102 894-2: first PathPoint relative to the reference position, each subsequent
    // one relative to the previous PathPoint (incremental deltas); newest first (RS_BSP_287).
    facilities::PathPoint prev = src.getReferencePoint();
    bool first_point = true; // only the first PathPoint may be clamped (stationary marker)

    for (const PathPoint& point : src.getConcisePointsMinLength(min_distance, max_points)) {
        auto delta_time = prev.time - point.time; // positive: point is in past
        auto delta_latitude = lround(point.latitude - prev.latitude, tenth_microdegree);
        auto delta_longitude = lround(point.longitude - prev.longitude, tenth_microdegree);

        if (delta_latitude < -131071 || delta_latitude > 131071) {
            continue; // delta latitude not encodable
        } else if (delta_longitude < -131071 || delta_longitude > 131071) {
            continue; // delta longitude not encodable
        } else if (delta_time >= scDeltaTimeStepLength) {
            if (delta_time > scMaxDeltaTime) {
                if (first_point) {
                    delta_time = scMaxDeltaTime; // RS_BSP_289: clamp the first PathPoint (stationary marker)
                } else {
                    break; // later overflow (old stationary) drops the disconnected older trail
                }
            }
            SomePathPoint* path_point = asn1::allocate<SomePathPoint>();
            path_point->pathPosition.deltaLatitude = delta_latitude;
            path_point->pathPosition.deltaLongitude = delta_longitude;
            path_point->pathPosition.deltaAltitude = DeltaAltitude::DeltaAltitude_unavailable;

            path_point->pathDeltaTime = asn1::allocate<SomePathDeltaTime>();
            *(path_point->pathDeltaTime) = delta_time.total_milliseconds() / scDeltaTimeStepLength.total_milliseconds();

            ASN_SEQUENCE_ADD(&dest, path_point);
            prev = point;
            first_point = false;
        }
    }
}

} // namespace facilities
} // namespace vanetza
