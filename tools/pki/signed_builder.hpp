#pragma once

#include "keys.hpp"
#include "signed_data.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <cstdint>

namespace vanetza
{
namespace pki
{

class Certificate;
class SecurityModule;

using security::HashAlgorithm;

// TS 103 097 protocol version that we emit on every constructed EtsiTs103097Data.
inline constexpr std::uint8_t ieee1609dot2_protocol_version = 3;

/**
 * Build an EtsiTs103097Data-Signed envelope carrying `payload` as inline
 * `unsecuredData`, signed with `signing_key`. PSID is fixed to SCR.
 *
 * \param signer_cert selects the SignerIdentifier variant per IEEE 1609.2 §5.3.1:
 *   nullptr  → signer = self    (hash of signer is hash of empty string)
 *   non-null → signer = digest  with HashedId8(cert); hash of signer is hash
 *              of the OER-encoded signer certificate.
 */
SignedData create_signed(const ByteBuffer& payload, SecurityModule& security,
    const PublicKey& signing_key, HashAlgorithm hash_algo, const Certificate* signer_cert);

/**
 * Build an EtsiTs103097Data-SignedExternalPayload (TS 102 941 §6.2.3.3.1) used
 * for the EC-signed proof inside an AT request: SignedData with
 * `extDataHash = hash_algo(external_payload)` and no inline data.
 *
 * The same `hash_algo` covers both the external-payload hash placed in
 * extDataHash and the signature hash chain. Other parameters mirror
 * create_signed(); PSID is fixed to SCR.
 */
SignedData create_external_signed(const ByteBuffer& external_payload, SecurityModule& security,
    const PublicKey& signing_key, HashAlgorithm hash_algo, const Certificate* signer_cert);

} // namespace pki
} // namespace vanetza
