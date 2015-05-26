#ifndef DATA_REQUEST_HPP_3JYISVXB
#define DATA_REQUEST_HPP_3JYISVXB

#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/traffic_class.hpp>
#include <vanetza/units/time.hpp>
#include <boost/optional.hpp>
#include <boost/variant.hpp>

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

    struct Repetition
    {
        units::Duration interval;
        units::Duration maximum;
    };

    UpperProtocol upper_protocol;
    CommunicationProfile communication_profile;
    bool security_profile;
    Lifetime maximum_lifetime;
    boost::optional<Repetition> repetition;
    unsigned max_hop_limit;
    TrafficClass traffic_class;
};

/**
 * Decrement maximum repetition by one interval
 * \param repetition Repetition data structure
 */
void decrement_by_one(DataRequest::Repetition& repetition);

/**
 * Request has to be repeated at least once more
 * \param request considered data request
 * \return true if there is at least one repetition left
 */
bool has_further_repetition(const DataRequest&);
bool has_further_repetition(const DataRequest::Repetition&);

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

using DataRequestVariant =
        boost::variant<
            GucDataRequest,
            GbcDataRequest,
            GacDataRequest,
            ShbDataRequest,
            TsbDataRequest
        >;

/**
 * Get access to common base data request class of all variants
 * \param variant DataRequestVariant object
 * \return referencet to underlying DataRequest
 */
DataRequest& access_request(DataRequestVariant&);

} // namespace geonet
} // namespace vanetza

#endif /* DATA_REQUEST_HPP_3JYISVXB */

