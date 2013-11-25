#include "basic_header.hpp"
#include "data_request.hpp"

namespace vanetza
{
namespace geonet
{

BasicHeader::BasicHeader(const MIB& mib) :
    version(mib.itsGnProtocolVersion),
    next_header(NextHeaderBasic::ANY),
    reserved(0),
    lifetime(mib.itsGnDefaultPacketLifetime),
    hop_limit(mib.itsGnDefaultHopLimit)
{
}

BasicHeader::BasicHeader(const DataRequest& request, const MIB& mib) :
    BasicHeader(mib)
{
    if (request.security_profile) {
        next_header = NextHeaderBasic::SECURED;
    } else {
        next_header = NextHeaderBasic::COMMON;
    }

    lifetime = request.maximum_lifetime;
    hop_limit = request.max_hop_limit;
}

BasicHeader::BasicHeader(const ShbDataRequest& request, const MIB& mib) :
    BasicHeader(static_cast<const DataRequest&>(request), mib)
{
    hop_limit = 1;
}

} // namespace geonet
} // namespace vanetza

