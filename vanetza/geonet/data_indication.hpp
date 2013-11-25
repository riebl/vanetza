#ifndef DATA_INDICATION_HPP_DOJK9Q8T
#define DATA_INDICATION_HPP_DOJK9Q8T

#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/interface.hpp>
#include <vanetza/geonet/position_vector.hpp>
#include <boost/optional.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace geonet
{

// forward declarations
struct BasicHeader;
struct CommonHeader;

struct DataIndication
{
    DataIndication();
    DataIndication(const BasicHeader&, const CommonHeader&);

    UpperProtocol upper_protocol;
    TransportType transport_type;
    boost::variant<Address, Area, std::nullptr_t> destination;
    ShortPositionVector source_position;
    // TODO: security report, certificate id and permissions are missing
    TrafficClass traffic_class;
    boost::optional<Lifetime> remaining_packet_lifetime;
    boost::optional<unsigned> remaining_hop_limit;
};

} // namespace geonet
} // namespace vanetza

#endif /* DATA_INDICATION_HPP_DOJK9Q8T */

