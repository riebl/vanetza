#ifndef DECAP_CONFIRM_HPP
#define DECAP_CONFIRM_HPP

#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/parsed_pdu.hpp>

namespace vanetza
{
namespace security
{

enum class ReportType : uint8_t
{
    Success,
    False_Signature,
    Invalid_Certificate,
    Revoked_Certificate,
    Incosistant_Chain,
    Invalid_Timestamp,
    Duplicate_Message,
    Invalid_Mobility_Data,
    Unsigned_Message,
    Signer_Certificate_Not_Found,
    Unsupported_Signer_Identifier_Type,
    Incompatible_Protocol,
    Unencrypted_Message,
    Decryption_Error,
};

/**
*   described in
*   TS 102 723-8 v1.0.0 (2013-07)
*   TS 102 636-4-1 v1.2.3 (2015-01)
*/
struct DecapConfirm
{
    // plaintext_packet_length is gathered via ByteBuffer::size(); valid range 0 ... 2^16-1; mandatory
    ByteBuffer plaintext_payload; // mandatory
    ReportType report; // mandatory
    boost::optional<uint64_t> certificate_id; // optional
    // member field 'permissions' currently not used; optional
};

} // namespace security
} // namespace vanetza

#endif // DECAP_CONFIRM_HPP
