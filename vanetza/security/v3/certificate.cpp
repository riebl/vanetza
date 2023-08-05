#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <boost/optional/optional.hpp>
#include <cstring>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{
bool copy_curve_point(PublicKey& to, const EccP256CurvePoint_t& from);
bool copy_curve_point(PublicKey& to, const EccP384CurvePoint_t& from);
ByteBuffer fetch_octets(const OCTET_STRING_t& octets);
}

Certificate::Certificate() :
    asn1::asn1c_oer_wrapper<EtsiTs103097Certificate_t>(asn_DEF_EtsiTs103097Certificate)
{
}

boost::optional<HashedId8> calculate_hash(const EtsiTs103097Certificate_t& cert)
{
    VerificationKeyIndicator_t indicator = cert.toBeSigned.verifyKeyIndicator;
    if (indicator.present != VerificationKeyIndicator_PR_verificationKey) {
        return boost::none;
    }

    ByteBuffer buffer = asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, &cert);
    switch (indicator.choice.verificationKey.present)
    {
        case PublicVerificationKey_PR_ecdsaNistP256:
        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
            return create_hashed_id8(calculate_sha256_digest(buffer.data(), buffer.size()));
            break;
        case PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
            return create_hashed_id8(calculate_sha384_digest(buffer.data(), buffer.size()));
            break;
        default:
            return boost::none;
            break;
    }
}

boost::optional<PublicKey> get_public_key(const EtsiTs103097Certificate_t& cert)
{
    VerificationKeyIndicator_t indicator = cert.toBeSigned.verifyKeyIndicator;
    if (indicator.present != VerificationKeyIndicator_PR_verificationKey) {
        return boost::none;
    }

    const PublicVerificationKey_t& input = cert.toBeSigned.verifyKeyIndicator.choice.verificationKey;
    PublicKey output;
    switch (input.present) {
        case PublicVerificationKey_PR_ecdsaNistP256:
            output.type = KeyType::NistP256;
            if (copy_curve_point(output, input.choice.ecdsaNistP256)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        case PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
            output.type = KeyType::BrainpoolP256r1;
            if (copy_curve_point(output, input.choice.ecdsaBrainpoolP256r1)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        case PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
            output.type = KeyType::BrainpoolP384r1;
            if (copy_curve_point(output, input.choice.ecdsaBrainpoolP384r1)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        default:
            return boost::none;
            break;
    }
}

ByteBuffer get_app_permissions(const EtsiTs103097Certificate_t& cert, ItsAid aid)
{
    ByteBuffer perms;
    const SequenceOfPsidSsp_t* seq = cert.toBeSigned.appPermissions;
    if (seq) {
        for (int i = 0; i < seq->list.count; ++i) {
            if (seq->list.array[i]->psid == aid && seq->list.array[i]->ssp != nullptr) {
                const ServiceSpecificPermissions_t& ssp = *seq->list.array[i]->ssp;
                if (ssp.present == ServiceSpecificPermissions_PR_bitmapSsp) {
                    const BitmapSsp_t& bitmap = ssp.choice.bitmapSsp;
                    perms.assign(bitmap.buf, bitmap.buf + bitmap.size);
                    break;
                }
            }
        }
    }
    return perms;
}

namespace
{

bool copy_curve_point(PublicKey& to, const EccP256CurvePoint_t& from)
{
    bool copied = true;
    switch (from.present) {
        case EccP256CurvePoint_PR_compressed_y_0:
            to.compression = KeyCompression::Y0;
            to.x = fetch_octets(from.choice.compressed_y_0);
            break;
        case EccP256CurvePoint_PR_compressed_y_1:
            to.compression = KeyCompression::Y1;
            to.x = fetch_octets(from.choice.compressed_y_1);
            break;
        case EccP256CurvePoint_PR_uncompressedP256:
            to.compression = KeyCompression::NoCompression;
            to.x = fetch_octets(from.choice.uncompressedP256.x);
            to.y = fetch_octets(from.choice.uncompressedP256.y);
            break;
        default:
            copied = false;
            break;
    }

    return copied;
}

bool copy_curve_point(PublicKey& to, const EccP384CurvePoint_t& from)
{
    bool copied = true;
    switch (from.present) {
        case EccP384CurvePoint_PR_compressed_y_0:
            to.compression = KeyCompression::Y0;
            to.x = fetch_octets(from.choice.compressed_y_0);
            break;
        case EccP384CurvePoint_PR_compressed_y_1:
            to.compression = KeyCompression::Y1;
            to.x = fetch_octets(from.choice.compressed_y_1);
            break;
        case EccP384CurvePoint_PR_uncompressedP384:
            to.compression = KeyCompression::NoCompression;
            to.x = fetch_octets(from.choice.uncompressedP384.x);
            to.y = fetch_octets(from.choice.uncompressedP384.y);
            break;
        default:
            copied = false;
            break;
    }

    return copied;
}

ByteBuffer fetch_octets(const OCTET_STRING_t& octets)
{
    ByteBuffer buffer(octets.size);
    std::memcpy(buffer.data(), octets.buf, octets.size);
    return buffer;
}

} // namespace

} // namespace v3
} // namespace security
} // namespace vanetza
