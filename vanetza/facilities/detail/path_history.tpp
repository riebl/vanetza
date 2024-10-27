#pragma once
#include <vanetza/facilities/path_history.hpp>
#include <vanetza/facilities/path_point.hpp>
#include <chrono>
#include <type_traits>

namespace vanetza
{
namespace facilities
{

template<typename SomePathSequence, typename SomePathPoint>
void copy(const facilities::PathHistory& src, SomePathSequence& dest)
{
    using SomePathDeltaTime = typename std::remove_pointer<decltype(SomePathPoint::pathDeltaTime)>::type;

    // TODO:  C2C-CC BSP allows up to 500m history for CAMs, we provide just minimal required history
    static const std::size_t scMaxPathPoints = 23;
    static const auto scDeltaTimeStepLength = boost::posix_time::milliseconds(10);
    static const auto scMaxDeltaTime = scDeltaTimeStepLength * 65535;

    const auto& concise_points = src.getConcisePoints();
    const facilities::PathPoint& ref = src.getReferencePoint();
    std::size_t path_points = 0;

    for (const PathPoint& point : concise_points) {
        auto delta_time = ref.time - point.time; // positive: point is in past
        auto delta_latitude = round(point.latitude - ref.latitude, tenth_microdegree); // positive: point is north
        auto delta_longitude = round(point.longitude - ref.longitude, tenth_microdegree); // positive: point is east

        if (path_points >= scMaxPathPoints) {
            // enough path points have been copied
            break;
        } else if (delta_latitude < -131071 || delta_latitude > 131071) {
            // delta latitude value cannot be encoded, skip this point
            continue;
        } else if (delta_longitude < -131071 || delta_longitude > 131071) {
            // delta longitude value cannot be encoded, skip this point
            continue;
        } else if (delta_time >= scDeltaTimeStepLength && delta_time <= scMaxDeltaTime) {
            SomePathPoint* path_point = asn1::allocate<SomePathPoint>();
            path_point->pathPosition.deltaLatitude = delta_latitude;
            path_point->pathPosition.deltaLongitude = delta_longitude;
            path_point->pathPosition.deltaAltitude = DeltaAltitude::DeltaAltitude_unavailable;

            path_point->pathDeltaTime = asn1::allocate<SomePathDeltaTime>();
            *(path_point->pathDeltaTime) = delta_time.total_milliseconds() / scDeltaTimeStepLength.total_milliseconds();

            ASN_SEQUENCE_ADD(&dest, path_point);
            ++path_points;
        }
    }
}

} // namespace facilities
} // namespace vanetza
