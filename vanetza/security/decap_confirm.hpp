#ifndef DECAP_CONFIRM_HPP
#define DECAP_CONFIRM_HPP

#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/extendet_pdu.hpp>

namespace vanetza
{
namespace security
{

enum class ReportType : uint8_t
{
    Success = 0,
    False_Signature = 1,
    Invalid_Certificate = 2,
    Revoked_Certificate = 3,
    Incosistant_Chain = 4,
    Invalid_Timestamp = 5,
    Duplicate_Message = 6,
    Invalid_Mobility_Data = 7,
    Unsigned_Message = 8,
    Signer_Certificate_Not_Found = 9,
    Unsupported_Signer_Identifier_Type = 10,
    Incompatible_Protocol = 11,
    Unencrypted_Message = 12,
    Decryption_Error = 13,
    Incompatible_Protocol = 14,
};

/**
*   described in
*   TS 102 723-8 v1.0.0 (2013-07)
*   TS 102 636-4-1 v1.2.3 (2015-01)
*/
template<class HEADER>
struct DecapConfirm
{
    // plaintext_packet_length is gathered via ByteBuffer::size(); valid range 0 ... 2^16-1; mandatory
    geonet::ExtendedPdu<HEADER> plaintext_pdu; // valid range plaintext_packet_length; mandatory
    ByteBuffer plaintext_payload; // mandatory
    ReportType report; // mandatory
    boost::optional<uint64_t> certificate_id // optional
    // member field 'permissions' currently not used; optional
};

} // namespace security
} // namespace vanetza

#endif // DECAP_CONFIRM_HPP
