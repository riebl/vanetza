#ifndef DATA_INDICATION_HPP_DOJK9Q8T
#define DATA_INDICATION_HPP_DOJK9Q8T

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/geonet/destination_variant.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/position_vector.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace geonet
{

struct DataIndication
{
    UpperProtocol upper_protocol;
    TransportType transport_type;
    DestinationVariant destination;
    ShortPositionVector source_position;
    security::DecapReport security_report;
    boost::optional<ItsAid> its_aid;
    boost::optional<ByteBuffer> permissions;
    // TODO: certificate id is missing (optional)
    TrafficClass traffic_class;
    boost::optional<Lifetime> remaining_packet_lifetime;
    boost::optional<unsigned> remaining_hop_limit;
};

} // namespace geonet
} // namespace vanetza

#endif /* DATA_INDICATION_HPP_DOJK9Q8T */
