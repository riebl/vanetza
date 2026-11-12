#include <vanetza/security/pqc/hybrid_certificate.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(PublicVerificationKey.h)
#include VANETZA_ASN1_SECURITY_HEADER(Signature.h)
#include VANETZA_ASN1_SECURITY_HEADER(ToBeSignedCertificate.h)
#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_crypto_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <limits>
#include <stdexcept>
#include <utility>

namespace vanetza
{
namespace security
{
namespace pqc
{

using v3::Certificate;
using v3::CertificateView;

namespace
{

boost::optional<Certificate> copy_certificate(const CertificateView& view)
{
    try {
        Certificate certificate;
        if (certificate.decode(view.encode())) {
            return certificate;
        }
    } catch (const std::exception&) {
        // A malformed or empty view cannot expose hybrid certificate data.
    }
    return boost::none;
}

Certificate copy_certificate_or_throw(const CertificateView& view)
{
    auto certificate = copy_certificate(view);
    if (!certificate) {
        throw std::invalid_argument("certificate cannot be encoded and decoded");
    }
    return std::move(*certificate);
}

ByteBuffer copy_octets(const OCTET_STRING_t& value)
{
    if (!value.buf || value.size == 0) {
        return {};
    }
    return ByteBuffer(value.buf, value.buf + value.size);
}

boost::optional<PublicKey> extract_alternative_public_key(const Certificate& certificate)
{
    const auto* key = certificate->toBeSigned.altVerificationKey;
    if (!key || key->present != Vanetza_Security_PublicVerificationKey_PR_fnDsa512) {
        return boost::none;
    }

    PublicKey result { copy_octets(key->choice.fnDsa512) };
    return result.bytes.size() == fndsa512_public_key_size ?
        boost::optional<PublicKey> { std::move(result) } : boost::none;
}

boost::optional<Signature> extract_alternative_signature(const Certificate& certificate)
{
    const auto* signature = certificate->toBeSigned.altSignatureValue;
    if (!signature || signature->present != Vanetza_Security_Signature_PR_fnDsa512Signature) {
        return boost::none;
    }

    Signature result { copy_octets(signature->choice.fnDsa512Signature) };
    return result.bytes.size() == fndsa512_signature_size ?
        boost::optional<Signature> { std::move(result) } : boost::none;
}

void assign_octets(OCTET_STRING_t& destination, const ByteBuffer& source)
{
    if (source.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
            OCTET_STRING_fromBuf(&destination,
                reinterpret_cast<const char*>(source.data()),
                static_cast<int>(source.size())) != 0) {
        throw std::runtime_error("cannot allocate ASN.1 octet string");
    }
}

void set_primary_signature(
    Certificate& certificate, const ::vanetza::security::Signature& signature)
{
    if (signature.r.size() != key_length(signature.type) ||
            signature.s.size() != key_length(signature.type)) {
        throw std::invalid_argument("ECC certificate signature has an invalid size");
    }

    if (certificate->signature) {
        vanetza::asn1::free(asn_DEF_Vanetza_Security_Signature, certificate->signature);
    }
    certificate->signature = vanetza::asn1::allocate<v3::asn1::Signature>();

    v3::asn1::EccP256CurvePoint* r256 = nullptr;
    v3::asn1::EccP384CurvePoint* r384 = nullptr;
    OCTET_STRING_t* s = nullptr;
    switch (signature.type) {
        case KeyType::NistP256:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            r256 = &certificate->signature->choice.ecdsaNistP256Signature.rSig;
            s = &certificate->signature->choice.ecdsaNistP256Signature.sSig;
            break;
        case KeyType::BrainpoolP256r1:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature;
            r256 = &certificate->signature->choice.ecdsaBrainpoolP256r1Signature.rSig;
            s = &certificate->signature->choice.ecdsaBrainpoolP256r1Signature.sSig;
            break;
        case KeyType::BrainpoolP384r1:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature;
            r384 = &certificate->signature->choice.ecdsaBrainpoolP384r1Signature.rSig;
            s = &certificate->signature->choice.ecdsaBrainpoolP384r1Signature.sSig;
            break;
        default:
            throw std::invalid_argument("unsupported ECC certificate signature type");
    }

    if (r256) {
        r256->present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
        assign_octets(r256->choice.x_only, signature.r);
    } else {
        r384->present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
        assign_octets(r384->choice.x_only, signature.r);
    }
    assign_octets(*s, signature.s);
}

const CertificateView& signing_certificate(
    const CertificateView& subject, const CertificateView* issuer)
{
    if (subject.issuer_is_self()) {
        return subject;
    }
    if (!issuer) {
        throw std::invalid_argument("issuer certificate is required for a non-self-signed certificate");
    }
    return *issuer;
}

ByteBuffer canonical_tbs(const CertificateView& subject, SignatureLayer layer)
{
    Certificate certificate = copy_certificate_or_throw(subject);
    if (layer == SignatureLayer::Alternative) {
        clear_alternative_signature(certificate);
    }

    auto canonical = certificate.canonicalize();
    if (!canonical) {
        throw std::invalid_argument("certificate cannot be canonicalized");
    }

    return vanetza::asn1::encode_oer(
        asn_DEF_Vanetza_Security_ToBeSignedCertificate, &canonical->content()->toBeSigned);
}

ByteBuffer canonical_issuer(CryptoProvider& crypto, const CertificateView& subject, const CertificateView* issuer)
{
    if (subject.issuer_is_self()) {
        return {};
    }
    if (!issuer) {
        throw std::invalid_argument("issuer certificate is required for a non-self-signed certificate");
    }

    const auto expected_digest = subject.issuer_digest();
    const auto actual_digest = issuer->calculate_digest(crypto);
    if (!expected_digest || !actual_digest || *expected_digest != *actual_digest) {
        throw std::invalid_argument("issuer certificate does not match the subject issuer identifier");
    }

    auto canonical = issuer->canonicalize();
    if (!canonical) {
        throw std::invalid_argument("issuer certificate cannot be canonicalized");
    }
    return canonical->encode();
}

} // namespace

boost::optional<PublicKey> get_alternative_public_key(const CertificateView& view)
{
    auto certificate = copy_certificate(view);
    return certificate ? extract_alternative_public_key(*certificate) : boost::none;
}

boost::optional<Signature> get_alternative_signature(const CertificateView& view)
{
    auto certificate = copy_certificate(view);
    return certificate ? extract_alternative_signature(*certificate) : boost::none;
}

MaterialState alternative_material_state(const CertificateView& view)
{
    auto certificate = copy_certificate(view);
    if (!certificate) {
        return MaterialState::Inconsistent;
    }

    const bool key_present = certificate->content()->toBeSigned.altVerificationKey;
    const bool signature_present = certificate->content()->toBeSigned.altSignatureValue;
    const bool has_key = static_cast<bool>(extract_alternative_public_key(*certificate));
    const bool has_signature = static_cast<bool>(extract_alternative_signature(*certificate));
    if (!key_present && !signature_present) {
        return MaterialState::None;
    }
    if (key_present != has_key || signature_present != has_signature) {
        return MaterialState::Inconsistent;
    }
    if (view.is_at_certificate()) {
        return !has_key && has_signature ? MaterialState::EndEntity : MaterialState::Inconsistent;
    }
    if (view.issuer_is_self() || view.is_ca_certificate()) {
        return has_key && has_signature ? MaterialState::Authority : MaterialState::Inconsistent;
    }
    return MaterialState::Inconsistent;
}

void set_alternative_public_key(Certificate& certificate, const PublicKey& key)
{
    if (key.bytes.size() != fndsa512_public_key_size) {
        throw std::invalid_argument("FN-DSA-512 public key has an invalid size");
    }
    clear_alternative_public_key(certificate);
    certificate->toBeSigned.altVerificationKey =
        vanetza::asn1::allocate<v3::asn1::PublicVerificationKey>();
    certificate->toBeSigned.altVerificationKey->present =
        Vanetza_Security_PublicVerificationKey_PR_fnDsa512;
    assign_octets(certificate->toBeSigned.altVerificationKey->choice.fnDsa512, key.bytes);
}

void set_alternative_signature(Certificate& certificate, const Signature& signature)
{
    if (signature.bytes.size() != fndsa512_signature_size) {
        throw std::invalid_argument("FN-DSA-512 signature has an invalid size");
    }
    clear_alternative_signature(certificate);
    certificate->toBeSigned.altSignatureValue =
        vanetza::asn1::allocate<v3::asn1::Signature>();
    certificate->toBeSigned.altSignatureValue->present =
        Vanetza_Security_Signature_PR_fnDsa512Signature;
    assign_octets(
        certificate->toBeSigned.altSignatureValue->choice.fnDsa512Signature,
        signature.bytes);
}

void clear_alternative_public_key(Certificate& certificate)
{
    if (certificate->toBeSigned.altVerificationKey) {
        vanetza::asn1::free(
            asn_DEF_Vanetza_Security_PublicVerificationKey,
            certificate->toBeSigned.altVerificationKey);
        certificate->toBeSigned.altVerificationKey = nullptr;
    }
}

void clear_alternative_signature(Certificate& certificate)
{
    if (certificate->toBeSigned.altSignatureValue) {
        vanetza::asn1::free(
            asn_DEF_Vanetza_Security_Signature,
            certificate->toBeSigned.altSignatureValue);
        certificate->toBeSigned.altSignatureValue = nullptr;
    }
}

ByteBuffer calculate_certificate_hash(
    CryptoProvider& crypto, HashAlgorithm algorithm,
    const CertificateView& subject,
    const CertificateView* issuer, SignatureLayer layer)
{
    if (algorithm == HashAlgorithm::Unspecified) {
        throw std::invalid_argument("certificate hash algorithm is unspecified");
    }

    const ByteBuffer data_input = canonical_tbs(subject, layer);
    const ByteBuffer signer_input = canonical_issuer(crypto, subject, issuer);
    const ByteBuffer data_hash = calculate_hash(crypto, algorithm, data_input);
    const ByteBuffer signer_hash = calculate_hash(crypto, algorithm, signer_input);

    ByteBuffer concatenated;
    concatenated.reserve(data_hash.size() + signer_hash.size());
    concatenated.insert(concatenated.end(), data_hash.begin(), data_hash.end());
    concatenated.insert(concatenated.end(), signer_hash.begin(), signer_hash.end());
    return calculate_hash(crypto, algorithm, concatenated);
}

void sign_primary_certificate(
    Certificate& subject, const CertificateView* issuer,
    ::vanetza::security::Backend& backend,
    const ::vanetza::security::PrivateKey& issuer_key)
{
    const CertificateView& signer = signing_certificate(subject, issuer);
    const auto public_key = v3::get_public_key(*copy_certificate_or_throw(signer).content());
    if (!public_key || public_key->type != issuer_key.type) {
        throw std::invalid_argument("ECC private key does not match the issuer certificate key type");
    }

    const HashAlgorithm algorithm = v3::specified_hash_algorithm(issuer_key.type);
    BackendCryptoProvider crypto { backend };
    const ByteBuffer digest = calculate_certificate_hash(
        crypto, algorithm, subject, issuer, SignatureLayer::Primary);
    const auto signature = backend.sign_digest(issuer_key, digest);
    if (!backend.verify_digest(*public_key, digest, signature)) {
        throw std::invalid_argument(
            "ECC private key does not match the issuer certificate public key");
    }
    set_primary_signature(subject, signature);
}

bool verify_primary_certificate(
    const CertificateView& subject, const CertificateView* issuer, CryptoProvider& crypto)
{
    try {
        const CertificateView& signer = signing_certificate(subject, issuer);
        Certificate signer_copy = copy_certificate_or_throw(signer);
        Certificate subject_copy = copy_certificate_or_throw(subject);
        const auto public_key = v3::get_public_key(*signer_copy.content());
        const auto signature = v3::get_signature(*subject_copy.content());
        if (!public_key || !signature || public_key->type != signature->type) {
            return false;
        }

        const HashAlgorithm algorithm = v3::specified_hash_algorithm(public_key->type);
        const ByteBuffer digest = calculate_certificate_hash(
            crypto, algorithm, subject, issuer, SignatureLayer::Primary);
        return verify_hash(crypto, algorithm, digest, *signature, *public_key).value_or(false);
    } catch (const std::exception&) {
        return false;
    }
}

void sign_alternative_certificate(
    Certificate& subject, const CertificateView* issuer,
    ::vanetza::security::Backend& hash_backend, Backend& backend,
    const PrivateKey& issuer_key)
{
    const CertificateView& signer = signing_certificate(subject, issuer);
    const auto public_key = get_alternative_public_key(signer);
    if (!public_key) {
        throw std::invalid_argument("issuer certificate has no FN-DSA-512 alternative key");
    }

    BackendCryptoProvider crypto { hash_backend };
    const ByteBuffer digest = calculate_certificate_hash(
        crypto, HashAlgorithm::SHA256, subject, issuer, SignatureLayer::Alternative);
    const auto signature = backend.sign(issuer_key, digest);
    if (!backend.verify(*public_key, digest, signature)) {
        throw std::invalid_argument(
            "FN-DSA-512 private key does not match the issuer certificate public key");
    }
    set_alternative_signature(subject, signature);
}

void sign_alternative_certificate(
    Certificate& subject, const CertificateView* issuer, CryptoProvider& crypto, Backend& backend,
    const KeyReference& issuer_key)
{
    const CertificateView& signer = signing_certificate(subject, issuer);
    const auto public_key = get_alternative_public_key(signer);
    if (!public_key) {
        throw std::invalid_argument("issuer certificate has no FN-DSA-512 alternative key");
    }

    const ByteBuffer digest = calculate_certificate_hash(
        crypto, HashAlgorithm::SHA256, subject, issuer, SignatureLayer::Alternative);
    const expected<Signature> signature = backend.sign(issuer_key, digest);
    if (!signature && signature.error() == SecurityModuleError::InvalidKeyReference) {
        throw std::invalid_argument("FN-DSA-512 key reference is unusable");
    } else if (!signature) {
        throw std::runtime_error("FN-DSA-512 signing failed");
    }
    if (!backend.verify(*public_key, digest, *signature)) {
        throw std::invalid_argument(
            "FN-DSA-512 private key does not match the issuer certificate public key");
    }
    set_alternative_signature(subject, *signature);
}

bool verify_alternative_certificate(
    const CertificateView& subject, const CertificateView* issuer, CryptoProvider& crypto, Backend& backend)
{
    try {
        const CertificateView& signer = signing_certificate(subject, issuer);
        const auto public_key = get_alternative_public_key(signer);
        const auto signature = get_alternative_signature(subject);
        if (!public_key || !signature) {
            return false;
        }

        const ByteBuffer digest = calculate_certificate_hash(
            crypto, HashAlgorithm::SHA256, subject, issuer, SignatureLayer::Alternative);
        return backend.verify(*public_key, digest, *signature);
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace pqc
} // namespace security
} // namespace vanetza
