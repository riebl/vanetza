#include "cohda_link.hpp"
#include "cohda.hpp"

void CohdaLink::request(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    insert_cohda_tx_header(request, packet);
    transmit(std::move(packet));
}

boost::optional<vanetza::EthernetHeader> CohdaLink::parse_ethernet_header(vanetza::CohesivePacket& packet) const
{
    return strip_cohda_rx_header(packet);
}
