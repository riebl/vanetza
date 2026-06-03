#pragma once

#include "certificate.hpp"
#include "response_codes.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace pki
{

class SecurityModule;

/**
 * \brief Decoded view of an InnerEcResponse payload.
 * \see TS 102 941 §6.2.3.2.2
 */
struct EnrolmentResponse
{
    EnrolmentResponseCode code; // EA's responseCode; parsing succeeds for any value
    ByteBuffer request_hash; // SHA-256 prefix of the matching request
    boost::optional<Certificate> certificate; // new EC; present iff one was decoded — caller must still check `code == ok`
};

/**
 * Parse a decrypted EnrolmentResponse per ETSI TS 102 941 §6.2.3.2.2.
 *
 * Verifies:
 *   - outer Ieee1609Dot2Data is signedData
 *   - signer = digest, matching HashedId8(ea_certificate)
 *   - tbsData.headerInfo.psid == aid::SCR
 *   - outer signature verifies against ea_certificate
 *   - inner EtsiTs102941Data.version == v1
 *   - inner content variant is enrolmentResponse
 *
 * For a non-ok responseCode the function returns normally and `code` holds it;
 * `certificate` is populated iff the response actually contains one.
 *
 * \throws DecodingFailure on structural failure
 * \throws VerificationFailure on signer-digest or signature mismatch
 */
EnrolmentResponse parse_enrolment_response(SecurityModule& security, const ByteBuffer& decrypted,
    const Certificate& ea_certificate);

} // namespace pki
} // namespace vanetza
