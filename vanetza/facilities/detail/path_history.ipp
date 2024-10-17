#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/BasicVehicleContainerLowFrequency.h>
#include <vanetza/asn1/its/r2/BasicVehicleContainerLowFrequency.h>
#include <vanetza/facilities/path_history.hpp>
#include <vanetza/facilities/detail/macros.ipp>

namespace vanetza
{
namespace facilities
{

// TODO:  C2C-CC BSP allows up to 500m history for CAMs, we provide just minimal required history
void copy(const facilities::PathHistory& ph, ASN1_PREFIXED(BasicVehicleContainerLowFrequency)& container)
{
    static const std::size_t scMaxPathPoints = 23;
    static const boost::posix_time::time_duration scMaxDeltaTime = boost::posix_time::millisec(655350);
    static const auto scMicrodegree = microdegree;

    const auto& concise_points = ph.getConcisePoints();
    const facilities::PathPoint& ref = ph.getReferencePoint();
    std::size_t path_points = 0;

    for (const PathPoint& point : concise_points) {
        auto delta_time = ref.time - point.time; // positive: point is in past
        auto delta_latitude = point.latitude - ref.latitude; // positive: point is north
        auto delta_longitude = point.longitude - ref.longitude; // positive: point is east

        while (!delta_time.is_negative() && path_points < scMaxPathPoints) {
            ::ASN1_PREFIXED(PathPoint)* path_point = asn1::allocate<::ASN1_PREFIXED(PathPoint)>();
            path_point->pathDeltaTime = asn1::allocate<ASN1_PREFIXED(PathDeltaTime_t)>();
            *(path_point->pathDeltaTime) = std::min(delta_time, scMaxDeltaTime).total_milliseconds() /
                10 * PathDeltaTime::PathDeltaTime_tenMilliSecondsInPast;
            path_point->pathPosition.deltaLatitude = (delta_latitude / scMicrodegree).value() *
                DeltaLatitude::DeltaLatitude_oneMicrodegreeNorth;
            path_point->pathPosition.deltaLongitude = (delta_longitude / scMicrodegree).value() *
                DeltaLongitude::DeltaLongitude_oneMicrodegreeEast;
            path_point->pathPosition.deltaAltitude = DeltaAltitude::DeltaAltitude_unavailable;

            ASN_SEQUENCE_ADD(&container.pathHistory, path_point);

            delta_time -= scMaxDeltaTime;
            ++path_points;
        }
    }
}

} // namespace facilities
} // namespace vanetza
