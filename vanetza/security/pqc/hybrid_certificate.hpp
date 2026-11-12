#pragma once

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{

class Backend;
class CryptoProvider;
struct PrivateKey;

namespace v3
{
class Certificate;
class CertificateView;
} // namespace v3

namespace pqc
{

/** The two nested certificate signatures used by the experimental profile. */
enum class SignatureLayer
{
    Alternative,
    Primary,
};

/** Shape of the optional alternative material carried by a certificate. */
enum class MaterialState
{
    None,
    Authority,
    EndEntity,
    Inconsistent,
};

boost::optional<PublicKey> get_alternative_public_key(const v3::CertificateView&);
boost::optional<Signature> get_alternative_signature(const v3::CertificateView&);
MaterialState alternative_material_state(const v3::CertificateView&);

void set_alternative_public_key(v3::Certificate&, const PublicKey&);
void set_alternative_signature(v3::Certificate&, const Signature&);
void clear_alternative_public_key(v3::Certificate&);
void clear_alternative_signature(v3::Certificate&);

/**
 * Calculate the certificate signature hash.
 *
 * The construction follows the IEEE 1609.2 certificate signature input:
 * H(H(COER(toBeSigned)) || H(COER(canonical issuer certificate))). For a
 * self-signed certificate the issuer input is empty. The alternative layer
 * omits altSignatureValue from toBeSigned; the primary layer includes it.
 */
ByteBuffer calculate_certificate_hash(
    CryptoProvider&, HashAlgorithm, const v3::CertificateView& subject,
    const v3::CertificateView* issuer, SignatureLayer);

/** Sign or verify the outer, classical certificate signature. */
void sign_primary_certificate(
    v3::Certificate&, const v3::CertificateView* issuer,
    ::vanetza::security::Backend&, const ::vanetza::security::PrivateKey& issuer_key);
bool verify_primary_certificate(
    const v3::CertificateView&, const v3::CertificateView* issuer, CryptoProvider&);

/** Sign or verify the inner FN-DSA-512 certificate signature. */
void sign_alternative_certificate(
    v3::Certificate&, const v3::CertificateView* issuer,
    ::vanetza::security::Backend& hash_backend, Backend&,
    const PrivateKey& issuer_key);
bool verify_alternative_certificate(
    const v3::CertificateView&, const v3::CertificateView* issuer, CryptoProvider&, Backend&);

} // namespace pqc
} // namespace security
} // namespace vanetza
