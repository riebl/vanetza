#ifndef DECAP_CONFIRM_HPP
#define DECAP_CONFIRM_HPP

#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/payload.hpp>
#include <boost/optional.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{

/**
 * SN-DECAP.confirm report codes
 * \see TS 102 723-8 v1.1.1 table 27
 */
enum class DecapReport
{
    Success,
    False_Signature,
    Invalid_Certificate,
    Revoked_Certificate,
    Inconsistant_Chain,
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
