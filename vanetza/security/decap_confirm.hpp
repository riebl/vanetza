#ifndef DECAP_CONFIRM_HPP
#define DECAP_CONFIRM_HPP

#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/security/certificate_validity.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <boost/optional.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{

/**
 * SN-DECAP.confirm report codes
 * \see TS 102 723-8 v1.1.1 table 27 or AUTOSAR SWS_V2xM_91000
 */
enum class DecapReport
{
    Success = 0x00,
    False_Signature = 0x01,
    Invalid_Certificate = 0x02,
    Revoked_Certificate = 0x03,
    Inconsistent_Chain = 0x04,
    Invalid_Timestamp = 0x05,
    Duplicate_Message = 0x06,
    Invalid_Mobility_Data = 0x07,
    Unsigned_Message = 0x08,
    Signer_Certificate_Not_Found = 0x09,
    Unsupported_Signer_Identifier_Type = 0x0a,
    Incompatible_Protocol = 0x0b,
    Unencrypted_Message = 0x0c,
    Decryption_Error = 0x0d,
    None = 0xff,
};

/** \brief contains output of the verify process
*   described in
*   TS 102 723-8 v1.0.0 (2013-07)
*   TS 102 636-4-1 v1.2.3 (2015-01)
*/
struct DecapConfirm
{
    // plaintext_packet_length is gathered via ByteBuffer::size(); valid range 0 ... 2^16-1; mandatory
    PacketVariant plaintext_payload; // mandatory
    DecapReport report; // mandatory
    CertificateValidity certificate_validity; // non-standard extension
    boost::optional<HashedId8> certificate_id; // optional
    ItsAid its_aid; // mandatory
    ByteBuffer permissions; // mandatory
};

} // namespace security
} // namespace vanetza

#endif // DECAP_CONFIRM_HPP
