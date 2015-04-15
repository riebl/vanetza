#ifndef PARSED_PDU_HPP_RUEHNJBY
#define PARSED_PDU_HPP_RUEHNJBY

#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/beacon_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/gbc_header.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace geonet
{

struct ParsedPdu
{
    BasicHeader basic;
    CommonHeader common;
    boost::variant<BeaconHeader, GeoBroadcastHeader, ShbHeader> extended;
};

std::unique_ptr<ParsedPdu> parse(PacketVariant&);
std::unique_ptr<ParsedPdu> parse(ChunkPacket&);
std::unique_ptr<ParsedPdu> parse(CohesivePacket&);

} // namespace geonet
} // namespace vanetza

#endif /* PARSED_PDU_HPP_RUEHNJBY */

