#ifndef DATA_REQUEST_HPP_3JYISVXB
#define DATA_REQUEST_HPP_3JYISVXB

#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/traffic_class.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace geonet
{

struct DataRequest
{
    DataRequest(const MIB& mib) :
        upper_protocol(UpperProtocol::BTP_A),
        communication_profile(CommunicationProfile::UNSPECIFIED),
        security_profile(false),
        maximum_lifetime(mib.itsGnDefaultPacketLifetime),
        max_hop_limit(mib.itsGnDefaultHopLimit),
        traffic_class(mib.itsGnDefaultTrafficClass)
    {}

    UpperProtocol upper_protocol;
    CommunicationProfile communication_profile;
    bool security_profile;
    Lifetime maximum_lifetime;
    boost::optional<unsigned> repetition_interval;
    boost::optional<unsigned> max_repetition_time;
    unsigned max_hop_limit;
    TrafficClass traffic_class;
};

/**
 * Check if packet shall be repeated according to request
 * \param request DataRequest of packet
 * \return true if repetition is requested
 */
inline bool is_repetition_requested(const DataRequest& request)
{
    return (request.repetition_interval && request.max_repetition_time);
}

struct DataRequestWithAddress : public DataRequest
{
    using DataRequest::DataRequest;
    Address destination;
};

struct DataRequestWithArea : public DataRequest
{
    using DataRequest::DataRequest;
    Area destination;
};

struct GucDataRequest : public DataRequestWithAddress
{
    using DataRequestWithAddress::DataRequestWithAddress;
};

struct GbcDataRequest : public DataRequestWithArea
{
    using DataRequestWithArea::DataRequestWithArea;
};

struct GacDataRequest : public DataRequestWithArea
{
    using DataRequestWithArea::DataRequestWithArea;
};

struct ShbDataRequest : public DataRequest
{
    using DataRequest::DataRequest;
};

struct TsbDataRequest : public DataRequest
{
    using DataRequest::DataRequest;
};

} // namespace geonet
} // namespace vanetza

#endif /* DATA_REQUEST_HPP_3JYISVXB */

