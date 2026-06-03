#pragma once

#include "keys.hpp"
#include "psid_ssp.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <boost/optional/optional.hpp>
#include <chrono>
#include <list>

namespace vanetza
{
namespace pki
{

class Certificate;
class EncryptedData;
class SecurityModule;

using security::HashAlgorithm;

/**
 * \brief Hint for sharedAtRequest.requestedSubjectAttributes.validityPeriod.
 * \see IEEE 1609.2 Time32 / Duration::hours
 */
struct ValidityPeriodHint
{
    Clock::time_point start;
    std::chrono::hours duration;
};

/**
 * \brief Parameters for an AuthorizationRequest (encryptedEcSignature variant).
 * \see TS 102 941 §6.2.3.3.1
 */
struct AuthorizationRequestParameters
{
    const Certificate* ec = nullptr; // current EC, signs the inner EC proof; mandatory
    const Certificate* ea_certificate = nullptr; // recipient of encryptedEcSignature; mandatory
    const Certificate* aa_certificate = nullptr; // recipient of outer encryption; mandatory
    PublicKey verification_key; // fresh key to be certified; private key in SecurityModule; mandatory
    boost::optional<PublicKey> at_encryption_key; // optional encryption key embedded in the AT
    std::list<PsidSsp> permissions; // requested PSID/SSP set; must be non-empty
    HashAlgorithm hash_algo = HashAlgorithm::SHA256; // EC proof and extDataHash; SHA-256 only
    boost::optional<ValidityPeriodHint> validity_period; // optional; AA decides within CP §7.2.1 bounds
    bool include_pop = true; // send AuthorizationRequestMessageWithPop; required by deployed AAs
};

/**
 * \brief Build the inner EtsiTs102941Data{authorizationRequest} plaintext.
 *
 * Exposed for testing; production code should call build_authorization_request().
 */
ByteBuffer build_signed_authorization_request(SecurityModule& security,
    const AuthorizationRequestParameters& parameters);

/**
 * \brief Build the AA-encrypted authorization request.
 *
 * Call .encode() on the result for the OER bytes to POST as `application/x-its-request`.
 */
EncryptedData build_authorization_request(SecurityModule& security, const AuthorizationRequestParameters& parameters);

} // namespace pki
} // namespace vanetza
