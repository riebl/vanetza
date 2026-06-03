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

// Result of parsing a decrypted AuthorizationResponse payload as specified
// in ETSI TS 102 941 §6.2.3.3.2.
struct AuthorizationResponse
{
    // Response code from InnerAtResponse. Parsing succeeds regardless of
    // the code value; the caller decides how to act on non-ok results.
    AuthorizationResponseCode code;

    // requestHash from InnerAtResponse (SHA-256 prefix of the request).
    ByteBuffer request_hash;

    // New Authorization Ticket returned by the AA. Present iff the parser
    // was able to decode a certificate; the caller must still check that
    // `code` is `ok` before relying on it.
    boost::optional<Certificate> certificate;
};

/**
 * Parse a decrypted AuthorizationResponse per TS 102 941 §6.2.3.3.2.
 *
 * Verifies:
 *   - outer Ieee1609Dot2Data is signedData
 *   - signer = digest, matching HashedId8(aa_certificate)
 *   - tbsData.headerInfo.psid == aid::SCR
 *   - outer signature verifies against aa_certificate
 *   - inner EtsiTs102941Data.version == v1
 *   - inner content variant is authorizationResponse
 *
 * If `code == ok` the message MUST carry a certificate per TS 102 941;
 * for non-ok codes the parser returns normally with whatever certificate
 * (if any) was provided.
 *
 * \throws DecodingFailure on structural failure or missing required certificate
 * \throws VerificationFailure on signer-digest or signature mismatch
 */
AuthorizationResponse parse_authorization_response(SecurityModule& security, const ByteBuffer& decrypted,
    const Certificate& aa_certificate);

} // namespace pki
} // namespace vanetza
