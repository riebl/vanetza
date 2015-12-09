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
#include <memory>

namespace vanetza
{
namespace geonet
{

struct ParsedPdu
{
    BasicHeader basic;
    CommonHeader common;
    HeaderVariant extended;
};

 /**
  * Parse just the BasicHeader from the given packet
  * \param packet
  * \return boost::optional<BasicHeader>
  */
boost::optional<BasicHeader> parse_basic(PacketVariant&);

 /**
  * Parse just the BasicHeader from the given packet
  * \param packet the CohesivePacket
  * \return boost::optional<BasicHeader>
  */
boost::optional<BasicHeader> parse_basic(CohesivePacket&);

 /**
  * Parse just the BasicHeader from the given packet
  * \param packet the ChunkPacket
  * \return boost::optional<BasicHeader>
  */
boost::optional<BasicHeader> parse_basic(ChunkPacket&);

 /**
  * CommonHeader in pdu defines which ExtendedHeader-type to choose
  * \param pdu
  * \param ar
  * \return std::size_t the ExtendedHeader-size
  */
std::size_t parse_extended(std::unique_ptr<ParsedPdu>&, InputArchive&);

 /**
  * Parse all but the BasicHeader from the given packet
  * \param packet
  * \return std::unique_ptr<ParsedPdu>
  */
std::unique_ptr<ParsedPdu> parse_header(PacketVariant&, BasicHeader&);

 /**
  * Parse all but the BasicHeader from the given packet
  * \param packet the BasicHeader
  * \return std::unique_ptr<ParsedPdu>
  */
std::unique_ptr<ParsedPdu> parse_header(CohesivePacket&, BasicHeader&);

 /**
  * Parse all but the BasicHeader from the given packet
  * \param packet the ChunkPacket
  * \return std::unique_ptr<ParsedPdu>
  */
std::unique_ptr<ParsedPdu> parse_header(ChunkPacket&);

 /**
  * Parse Common-Header and Extended-Header from the given ByteBuffer
  * \param data_buffer
  * \param basic
  * \return std::unique_ptr<ParsedPdu>
  */
std::unique_ptr<ParsedPdu> parse_secured_header(const ByteBuffer&, const BasicHeader&);

 /**
  * Extract just the SecuredMessage from the packet
  * \param packet
  * \return boost::optional<security::SecuredMessage>
  */
boost::optional<security::SecuredMessage> extract_secured_message(PacketVariant&);

 /**
  * Deserialize SecuredMessage from ByteBuffer
  * \param secured_buffer
  * \return boost::optional<security::SecuredMessage>
  */
boost::optional<security::SecuredMessage> extract_secured_message(ByteBuffer);

 /**
  * Extract just the SecuredMessage from the packet
  * \param packet the CohesivePacket
  * \return boost::optional<security::SecuredMessage>
  */
boost::optional<security::SecuredMessage> extract_secured_message(CohesivePacket&);

 /**
  * Extract just the SecuredMessage from the packet
  * \param packet the ChunkPacket
  * \return boost::optional<security::SecuredMessage>
  */
boost::optional<security::SecuredMessage> extract_secured_message(ChunkPacket&);

ByteBuffer convert_for_signing(const ParsedPdu& pdu);

} // namespace geonet
} // namespace vanetza

#endif /* PARSED_PDU_HPP_RUEHNJBY */
