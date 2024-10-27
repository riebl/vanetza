#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/BasicVehicleContainerLowFrequency.h>
#include <vanetza/asn1/its/PathHistory.h>
#include <vanetza/asn1/its/r2/BasicVehicleContainerLowFrequency.h>
#include <vanetza/asn1/its/r2/Path.h>
#include <vanetza/asn1/its/r2/PathHistory.h>
#include <vanetza/facilities/detail/macros.ipp>
#include <vanetza/facilities/detail/path_history.tpp>

namespace vanetza
{
namespace facilities
{

static_assert(DeltaLongitude_oneMicrodegreeEast == 10, "DeltaLongitude is an integer number of tenth microdegrees");
static_assert(DeltaLatitude_oneMicrodegreeNorth == 10, "DeltaLatitude is an integer number of tenth microdegrees");
static_assert(PathDeltaTime_tenMilliSecondsInPast == 1, "PathDeltaTime encodes 10ms steps");

void copy(const facilities::PathHistory& src, ASN1_PREFIXED(PathHistory_t)& dest)
{
    copy<ASN1_PREFIXED(PathHistory_t), ASN1_PREFIXED(PathPoint_t)>(src, dest);
}

#if ITS_RELEASE != 1
// no Path_t in ITS Release 1 ASN.1
void copy(const facilities::PathHistory& src, ASN1_PREFIXED(Path_t)& dest)
{
    copy<ASN1_PREFIXED(Path_t), ASN1_PREFIXED(PathPoint_t)>(src, dest);
}
#endif

void copy(const facilities::PathHistory& ph, ASN1_PREFIXED(BasicVehicleContainerLowFrequency)& container)
{
    copy(ph, container.pathHistory);
}

} // namespace facilities
} // namespace vanetza
