#include "common_header.hpp"
#include "data_request.hpp"
#include <stdexcept>

namespace vanetza
{
namespace geonet
{

CommonHeader::CommonHeader() :
    next_header(NextHeaderCommon::ANY),
    reserved1(0),
    header_type(HeaderType::ANY),
    flags(0),
    payload(0),
    maximum_hop_limit(0),
    reserved2(0)
{
}

CommonHeader::CommonHeader(const MIB& mib) :
    next_header(NextHeaderCommon::ANY),
    reserved1(0),
    header_type(HeaderType::ANY),
    traffic_class(mib.itsGnDefaultTrafficClass),
    flags(mib.itsGnIsMobile ? 0x80 : 0x00),
    payload(0),
    maximum_hop_limit(mib.itsGnDefaultHopLimit),
    reserved2(0)
{
}

CommonHeader::CommonHeader(const DataRequest& request, const MIB& mib) :
    CommonHeader(mib)
{
    switch (request.upper_protocol) {
        case UpperProtocol::BTP_A:
            next_header = NextHeaderCommon::BTP_A;
            break;
        case UpperProtocol::BTP_B:
            next_header = NextHeaderCommon::BTP_B;
            break;
        case UpperProtocol::IPv6:
            next_header = NextHeaderCommon::IPv6;
            break;
        default:
            throw std::runtime_error("Unhandled upper protocol");
            break;
    }

    traffic_class = request.traffic_class;
    maximum_hop_limit = request.max_hop_limit;
}

CommonHeader::CommonHeader(const ShbDataRequest& request, const MIB& mib) :
    CommonHeader(static_cast<const DataRequest&>(request), mib)
{
    header_type = HeaderType::TSB_SINGLE_HOP;
    maximum_hop_limit = 1;
}

} // namespace geonet
} // namespace vanetza

