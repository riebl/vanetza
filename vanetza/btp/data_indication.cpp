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
    transport_type(ind.transport_type),
    destination(ind.destination),
    security_report(ind.security_report),
    certificate_id(ind.certificate_id),
    its_aid(ind.its_aid),
    permissions(ind.permissions),
    source_position(ind.source_position),
    traffic_class(ind.traffic_class),
    remaining_packet_lifetime(ind.remaining_packet_lifetime),
    remaining_hop_limit(ind.remaining_hop_limit)
{
}

DataIndication::DataIndication(const geonet::DataIndication& ind, const HeaderB& btp) :
    destination_port(btp.destination_port),
    destination_port_info(btp.destination_port_info),
    transport_type(ind.transport_type),
    destination(ind.destination),
    security_report(ind.security_report),
    certificate_id(ind.certificate_id),
    its_aid(ind.its_aid),
    permissions(ind.permissions),
    source_position(ind.source_position),
    traffic_class(ind.traffic_class),
    remaining_packet_lifetime(ind.remaining_packet_lifetime),
    remaining_hop_limit(ind.remaining_hop_limit)
{
}

} // namespace btp
} // namespace vanetza
