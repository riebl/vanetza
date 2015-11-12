#ifndef PARSED_PDU_HPP_RUEHNJBY
#define PARSED_PDU_HPP_RUEHNJBY

#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/security/secured_message.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace geonet
{

struct ParsedPdu
{
    BasicHeader basic;
    boost::optional<security::SecuredMessage> secured;
    CommonHeader common;
    HeaderVariant extended;
};

std::unique_ptr<ParsedPdu> parse(PacketVariant&);
std::unique_ptr<ParsedPdu> parse(ChunkPacket&);
std::unique_ptr<ParsedPdu> parse(CohesivePacket&);

ByteBuffer convert_for_signing(const ParsedPdu& pdu);

} // namespace geonet
} // namespace vanetza

#endif /* PARSED_PDU_HPP_RUEHNJBY */

