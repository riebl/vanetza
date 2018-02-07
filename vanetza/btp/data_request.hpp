#ifndef DATA_REQUEST_HPP_BSJC1VFV
#define DATA_REQUEST_HPP_BSJC1VFV

#include <vanetza/btp/header.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/destination_variant.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/lifetime.hpp>
#include <vanetza/geonet/traffic_class.hpp>

namespace vanetza
{
namespace btp
{

struct DataRequestGeoNetParams
{
    geonet::TransportType transport_type;
    geonet::DestinationVariant destination;
    geonet::CommunicationProfile communication_profile;
    ItsAid its_aid;
    boost::optional<geonet::Lifetime> maximum_lifetime;
    boost::optional<unsigned> maximum_hop_limit;
    boost::optional<geonet::DataRequest::Repetition> repetition;
    geonet::TrafficClass traffic_class;
};

struct DataRequestA
{
    DataRequestA();

    decltype(HeaderA::destination_port) destination_port;
    decltype(HeaderA::source_port) source_port;
    DataRequestGeoNetParams gn;
};

struct DataRequestB
{
    DataRequestB();

    decltype(HeaderB::destination_port) destination_port;
    decltype(HeaderB::destination_port_info) destination_port_info;
    DataRequestGeoNetParams gn;
};

} // namespace btp
} // namespace vanetza

#endif /* DATA_REQUEST_HPP_BSJC1VFV */
