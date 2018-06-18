#ifndef DATA_REQUEST_HPP_3JYISVXB
#define DATA_REQUEST_HPP_3JYISVXB

#include <vanetza/common/channel.hpp>
#include <vanetza/common/its_aid.hpp>
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

// forward declaration
namespace btp { struct DataRequestB; }

namespace geonet
{

struct DataRequest
{
    DataRequest(const MIB& mib, ItsAid its_aid = 0) :
        upper_protocol(UpperProtocol::BTP_A),
        communication_profile(CommunicationProfile::UNSPECIFIED),
        its_aid(its_aid),
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
    ItsAid its_aid;
    Lifetime maximum_lifetime;
    boost::optional<Repetition> repetition;
    unsigned max_hop_limit;
    TrafficClass traffic_class;
    Channel channel;
};

/**
 * \brief Decrement maximum repetition by one interval
 * \param repetition Repetition data structure
 */
void decrement_by_one(DataRequest::Repetition& repetition);

/**
 * \brief Test if request has to be repeated at least once more
 * \param request DataRequest
 * \return true if there is at least one repetition left
 */
bool has_further_repetition(const DataRequest&);

/**
 * \brief Test if at least one repetition is outstanding
 * \param repetition
 * \return true if there is at least one repetition left
 */
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
 * \return reference to underlying DataRequest
 */
DataRequest& access_request(DataRequestVariant&);

/**
 * Copy request parameters from BTP-B request
 * \param btp BTP-B data request
 * \param gn GeoNet destination request
 */
void copy_request_parameters(const btp::DataRequestB& btp, DataRequest& gn);
void copy_request_parameters(const btp::DataRequestB& btp, DataRequestWithAddress& gn);
void copy_request_parameters(const btp::DataRequestB& btp, DataRequestWithArea& gn);

} // namespace geonet
} // namespace vanetza

#endif /* DATA_REQUEST_HPP_3JYISVXB */
