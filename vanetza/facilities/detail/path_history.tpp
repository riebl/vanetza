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
        auto delta_latitude = point.latitude - ref.latitude; // positive: point is north
        auto delta_longitude = point.longitude - ref.longitude; // positive: point is east

        if (delta_time >= scDeltaTimeStepLength && delta_time <= scMaxDeltaTime && path_points < scMaxPathPoints) {
            SomePathPoint* path_point = asn1::allocate<SomePathPoint>();
            path_point->pathDeltaTime = asn1::allocate<SomePathDeltaTime>();
            *(path_point->pathDeltaTime) = delta_time.total_milliseconds() / scDeltaTimeStepLength.total_milliseconds();
            path_point->pathPosition.deltaLatitude = round(delta_latitude, tenth_microdegree);
            path_point->pathPosition.deltaLongitude = round(delta_longitude, tenth_microdegree);
            path_point->pathPosition.deltaAltitude = DeltaAltitude::DeltaAltitude_unavailable;

            ASN_SEQUENCE_ADD(&dest, path_point);
            ++path_points;
        }
    }
}

} // namespace facilities
} // namespace vanetza
