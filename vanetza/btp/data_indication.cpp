#include "data_indication.hpp"
#include "header.hpp"
#include <vanetza/geonet/data_indication.hpp>

namespace vanetza
{
namespace btp
{

DataIndication::DataIndication()
{
}

DataIndication::DataIndication(const geonet::DataIndication& ind, const HeaderA& btp) :
    source_port(btp.source_port),
    destination_port(btp.destination_port),
    destination(ind.destination),
    its_aid(ind.its_aid),
    permissions(ind.permissions),
    source_position(ind.source_position),
    traffic_class(ind.traffic_class),
    remaining_packet_lifetime(ind.remaining_packet_lifetime)
{
}

DataIndication::DataIndication(const geonet::DataIndication& ind, const HeaderB& btp) :
    destination_port(btp.destination_port),
    destination_port_info(btp.destination_port_info),
    destination(ind.destination),
    its_aid(ind.its_aid),
    permissions(ind.permissions),
    source_position(ind.source_position),
    traffic_class(ind.traffic_class),
    remaining_packet_lifetime(ind.remaining_packet_lifetime)
{
}

} // namespace btp
} // namespace vanetza
