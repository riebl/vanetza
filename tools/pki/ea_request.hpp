#pragma once

#include "keys.hpp"
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <string>

namespace vanetza
{
namespace pki
{

class Certificate;
class EncryptedData;
class SecurityModule;

using security::HashAlgorithm;

/**
 * \brief Parameters for an InnerEcRequest / outer EtsiTs103097Data-Signed enrolment message.
 * \see TS 102 941 §6.2.3.2
 */
struct EnrolmentRequestParameters
{
    std::string its_id; // canonical id (initial) or current EC HashedId8 (re-enrolment)
    PublicKey verification_key; // to be certified; private key in SecurityModule for POP signature
    PublicKey outer_signer_key; // signs outer Data-Signed; canonical key (initial) or current EC verification key (re-enrolment)
    HashAlgorithm hash_algo = HashAlgorithm::SHA256; // POP and outer signatures
    const Certificate* outer_signer_certificate = nullptr; // null → signer=self; non-null → signer=digest of this cert
};

/**
 * \brief Build the signed (but not yet encrypted) enrolment request payload.
 *
 * Layered signatures: outer EtsiTs103097Data-Signed (signed with outer_signer_key;
 * signer=self for initial enrolment, digest(outer_signer_certificate) for re-keying)
 * wraps EtsiTs102941Data{enrolmentRequest=InnerEcRequestSignedForPop}, which is
 * the OER-encoded InnerEcRequest signed with verification_key (signer=self) as POP.
 * Exposed for testing; production code should call build_enrolment_request().
 */
ByteBuffer build_signed_enrolment_request(SecurityModule& security, const EnrolmentRequestParameters& parameters);

/**
 * \brief Build the EA-encrypted enrolment request.
 *
 * Call .encode() on the result for the OER bytes to POST. The ECIES context
 * held in the returned EncryptedData is also needed to decrypt the EA's
 * response (same symmetric key via pskRecipInfo).
 */
EncryptedData build_enrolment_request(SecurityModule& security, const EnrolmentRequestParameters& parameters,
    const Certificate& ea_certificate);

} // namespace pki
} // namespace vanetza
