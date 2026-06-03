#include "keys.hpp"
#include "asn1.hpp"
#include "openssl.hpp"
#include <vanetza/asn1/security/PublicEncryptionKey.h>
#include <vanetza/asn1/security/PublicVerificationKey.h>
#include <vanetza/asn1/security/Signature.h>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

static ByteBuffer get_x_coordinate(const Vanetza_Security_EccP256CurvePoint_t& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            return copy(point.choice.compressed_y_0);
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            return copy(point.choice.compressed_y_1);
        case Vanetza_Security_EccP256CurvePoint_PR_x_only:
            return copy(point.choice.x_only);
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            return copy(point.choice.uncompressedP256.x);
        default:
            return {};
    }
}

static ByteBuffer get_x_coordinate(const Vanetza_Security_EccP384CurvePoint_t& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
            return copy(point.choice.compressed_y_0);
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            return copy(point.choice.compressed_y_1);
        case Vanetza_Security_EccP384CurvePoint_PR_x_only:
            return copy(point.choice.x_only);
        case Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384:
            return copy(point.choice.uncompressedP384.x);
        default:
            return {};
    }
}

Signature make_signature(const struct Vanetza_Security_Signature& asn)
{
    Signature sig;
    switch (asn.present) {
        case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
            sig.type = KeyType::NistP256;
            sig.r = get_x_coordinate(asn.choice.ecdsaNistP256Signature.rSig);
            sig.s = copy(asn.choice.ecdsaNistP256Signature.sSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
            sig.type = KeyType::BrainpoolP256r1;
            sig.r = get_x_coordinate(asn.choice.ecdsaBrainpoolP256r1Signature.rSig);
            sig.s = copy(asn.choice.ecdsaBrainpoolP256r1Signature.sSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            sig.type = KeyType::BrainpoolP384r1;
            sig.r = get_x_coordinate(asn.choice.ecdsaBrainpoolP384r1Signature.rSig);
            sig.s = copy(asn.choice.ecdsaBrainpoolP384r1Signature.sSig);
            break;
        default:
            sig.type = KeyType::Unspecified;
            break;
    }

    return sig;
}

PublicKey derive_public_key(const PrivateKey& priv)
{
    auto ec_key = make_ec_key(priv);
    return make_public_key(ec_key.raw());
}

void set_verification_key(Vanetza_Security_PublicVerificationKey& dst, const PublicKey& key)
{
    switch (key.type) {
        case KeyType::NistP256:
            dst.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
            fill_curve_point(key, dst.choice.ecdsaNistP256);
            break;
        case KeyType::BrainpoolP256r1:
            dst.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
            fill_curve_point(key, dst.choice.ecdsaBrainpoolP256r1);
            break;
        case KeyType::BrainpoolP384r1:
            dst.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
            fill_curve_point(key, dst.choice.ecdsaBrainpoolP384r1);
            break;
        default:
            throw std::invalid_argument("unsupported verification key type");
    }
}

void set_encryption_key(Vanetza_Security_PublicEncryptionKey& dst, const PublicKey& key)
{
    dst.supportedSymmAlg = Vanetza_Security_SymmAlgorithm_aes128Ccm;
    switch (key.type) {
        case KeyType::NistP256:
            dst.publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
            fill_curve_point(key, dst.publicKey.choice.eciesNistP256);
            break;
        case KeyType::BrainpoolP256r1:
            dst.publicKey.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesBrainpoolP256r1;
            fill_curve_point(key, dst.publicKey.choice.eciesBrainpoolP256r1);
            break;
        default:
            throw std::invalid_argument("unsupported encryption key type");
    }
}

} // namespace pki
} // namespace vanetza
