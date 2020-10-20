#ifndef COHDA_LINK_HPP_IXOCQ5RH
#define COHDA_LINK_HPP_IXOCQ5RH

#include "raw_socket_link.hpp"

class CohdaLink : public RawSocketLink
{
public:
    using RawSocketLink::RawSocketLink;

    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;

protected:
    boost::optional<vanetza::EthernetHeader> parse_ethernet_header(vanetza::CohesivePacket&) const override;
};

#endif /* COHDA_LINK_HPP_IXOCQ5RH */

