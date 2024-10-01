#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <boost/optional/optional.hpp>
#include <cassert>
#include <cstring>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{
bool copy_curve_point(PublicKey& to, const asn1::EccP256CurvePoint& from);
bool copy_curve_point(PublicKey& to, const asn1::EccP384CurvePoint& from);
ByteBuffer fetch_octets(const OCTET_STRING_t& octets);

bool is_compressed(const Vanetza_Security_EccP256CurvePoint& point);
bool is_compressed(const Vanetza_Security_EccP384CurvePoint& point);
bool is_signature_x_only(const Vanetza_Security_Signature_t& sig);
bool compress(Vanetza_Security_EccP256CurvePoint&);
bool compress(Vanetza_Security_EccP384CurvePoint&);
bool make_x_only(Vanetza_Security_EccP256CurvePoint&);
bool make_x_only(Vanetza_Security_EccP384CurvePoint&);
bool make_signature_x_only(Vanetza_Security_Signature_t& sig);

} // namespace

Certificate::Certificate() :
    asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Certificate>(asn_DEF_Vanetza_Security_EtsiTs103097Certificate)
{
}

Certificate::Certificate(const asn1::EtsiTs103097Certificate& cert) :
    asn1::asn1c_oer_wrapper<asn1::EtsiTs103097Certificate>(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &cert)
{
}

boost::optional<HashedId8> Certificate::calculate_digest() const
{
    return v3::calculate_digest(*content());
}

KeyType Certificate::get_verification_key_type() const
{
    return v3::get_verification_key_type(*content());
}

bool is_canonical(const asn1::EtsiTs103097Certificate& cert)
{
    bool compressed_point = true;
    const Vanetza_Security_VerificationKeyIndicator& indicator = cert.toBeSigned.verifyKeyIndicator;
    if (indicator.present == Vanetza_Security_VerificationKeyIndicator_PR_verificationKey) {
        const Vanetza_Security_PublicVerificationKey& pubkey = indicator.choice.verificationKey;
        switch (pubkey.present) {
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
                compressed_point = is_compressed(pubkey.choice.ecdsaNistP256);
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                compressed_point = is_compressed(pubkey.choice.ecdsaBrainpoolP256r1);
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
                compressed_point = is_compressed(pubkey.choice.ecdsaBrainpoolP384r1);
                break;
            default:
                break;
        }
    } else if (indicator.present == Vanetza_Security_VerificationKeyIndicator_PR_reconstructionValue) {
        compressed_point = is_compressed(indicator.choice.reconstructionValue);
    }

    if (!compressed_point) {
        return false;
    } else if (cert.signature && !is_signature_x_only(*cert.signature)) {
        return false;
    } else {
        return true;
    }
}

boost::optional<Certificate> canonicalize(const asn1::EtsiTs103097Certificate& cert)
{
    Certificate canonical { cert };
    bool success = true;

    if (canonical->toBeSigned.verifyKeyIndicator.present == Vanetza_Security_VerificationKeyIndicator_PR_verificationKey) {
        Vanetza_Security_PublicVerificationKey& pubkey = canonical->toBeSigned.verifyKeyIndicator.choice.verificationKey;
        switch (pubkey.present) {
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
                success &= compress(pubkey.choice.ecdsaNistP256);
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                success &= compress(pubkey.choice.ecdsaBrainpoolP256r1);
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
                success &= compress(pubkey.choice.ecdsaBrainpoolP384r1);
                break;
            default:
                break;
        }
    } else if (canonical->toBeSigned.verifyKeyIndicator.present == Vanetza_Security_VerificationKeyIndicator_PR_reconstructionValue) {
        success &= compress(canonical->toBeSigned.verifyKeyIndicator.choice.reconstructionValue);
    }

    if (canonical->signature) {
        success &= make_signature_x_only(*canonical->signature);
    }

    if (success) {
        assert(is_canonical(*canonical));
        return canonical;
    } else {
        return boost::none;
    }
}

boost::optional<HashedId8> calculate_digest_internal(const asn1::EtsiTs103097Certificate& cert, KeyType key_type)
{
    boost::optional<HashedId8> digest;

    try {
        ByteBuffer buffer = asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &cert);

        switch (key_type)
        {
            case KeyType::NistP256:
            case KeyType::BrainpoolP256r1:
                digest = create_hashed_id8(calculate_sha256_digest(buffer.data(), buffer.size()));
                break;
            case KeyType::BrainpoolP384r1:
                digest = create_hashed_id8(calculate_sha384_digest(buffer.data(), buffer.size()));
                break;
            default:
                break;
        }
    } catch (const std::exception&) {
        // cannot calculate digest of non-encodable certificate
    }

    return digest;
}

boost::optional<HashedId8> calculate_digest(const asn1::EtsiTs103097Certificate& cert)
{
    boost::optional<HashedId8> digest;
    auto key_type = get_verification_key_type(cert);
    if (key_type != KeyType::Unspecified) {
        if (is_canonical(cert)) {
            digest = calculate_digest_internal(cert, key_type);
        } else {
            auto maybe_canonical_cert = canonicalize(cert);
            if (maybe_canonical_cert) {
                digest = calculate_digest_internal(*maybe_canonical_cert.value(), key_type);
            }
        }
    }
    return digest;
}

KeyType get_verification_key_type(const asn1::EtsiTs103097Certificate& cert)
{
    KeyType key_type = KeyType::Unspecified;

    if (cert.toBeSigned.verifyKeyIndicator.present == Vanetza_Security_VerificationKeyIndicator_PR_verificationKey)
    {
        switch (cert.toBeSigned.verifyKeyIndicator.choice.verificationKey.present)
        {
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
                key_type = KeyType::NistP256;
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                key_type = KeyType::BrainpoolP256r1;
                break;
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
                key_type = KeyType::BrainpoolP384r1;
                break;
            default:
                break;
        }
    }

    return key_type;
}

boost::optional<PublicKey> get_public_key(const asn1::EtsiTs103097Certificate& cert)
{
  asn1::VerificationKeyIndicator indicator = cert.toBeSigned.verifyKeyIndicator;
    if (indicator.present != Vanetza_Security_VerificationKeyIndicator_PR_verificationKey) {
        return boost::none;
    }

    const asn1::PublicVerificationKey& input = cert.toBeSigned.verifyKeyIndicator.choice.verificationKey;
    PublicKey output;
    switch (input.present) {
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
            output.type = KeyType::NistP256;
            if (copy_curve_point(output, input.choice.ecdsaNistP256)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
            output.type = KeyType::BrainpoolP256r1;
            if (copy_curve_point(output, input.choice.ecdsaBrainpoolP256r1)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
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

ByteBuffer get_app_permissions(const asn1::EtsiTs103097Certificate& cert, ItsAid aid)
{
    ByteBuffer perms;
    const asn1::SequenceOfPsidSsp* seq = cert.toBeSigned.appPermissions;
    if (seq) {
        for (int i = 0; i < seq->list.count; ++i) {
            if (seq->list.array[i]->psid == aid && seq->list.array[i]->ssp != nullptr) {
                const asn1::ServiceSpecificPermissions& ssp = *seq->list.array[i]->ssp;
                if (ssp.present == Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp) {
                    const asn1::BitmapSsp& bitmap = ssp.choice.bitmapSsp;
                    perms.assign(bitmap.buf, bitmap.buf + bitmap.size);
                    break;
                }
            }
        }
    }
    return perms;
}

void add_psid_group_permission(asn1::PsidGroupPermissions* group_permission, ItsAid aid, const ByteBuffer& ssp, const ByteBuffer& bitmask)
{
    auto psid_range_scr = asn1::allocate<asn1::PsidSspRange>();
    psid_range_scr->psid = aid;
    psid_range_scr->sspRange = asn1::allocate<asn1::SspRange>();
    psid_range_scr->sspRange->present = Vanetza_Security_SspRange_PR_bitmapSspRange;
    OCTET_STRING_fromBuf(
        &psid_range_scr->sspRange->choice.bitmapSspRange.sspValue,
        reinterpret_cast<const char*>(ssp.data()),
        ssp.size()
    );
    OCTET_STRING_fromBuf(
        &psid_range_scr->sspRange->choice.bitmapSspRange.sspBitmask,
        reinterpret_cast<const char*>(bitmask.data()),
        bitmask.size()
    );
    ASN_SEQUENCE_ADD(&group_permission->subjectPermissions.choice.Explicit, psid_range_scr);
}

void add_app_permissions(Certificate& cert, ItsAid aid)
{
    asn1::SequenceOfPsidSsp* seq = cert->toBeSigned.appPermissions;
    if (!seq) {
        seq = asn1::allocate<asn1::SequenceOfPsidSsp>();
        cert->toBeSigned.appPermissions = seq;
    }
    // Allocate the memory
    auto psid_ptr = asn1::allocate<asn1::PsidSsp>();
    psid_ptr->psid = aid;
    ASN_SEQUENCE_ADD(seq, psid_ptr);
}

void Certificate::add_permission(ItsAid aid, const ByteBuffer& ssp)
{
    asn1::SequenceOfPsidSsp* seq = m_struct->toBeSigned.appPermissions;
    if (!seq) {
        seq = asn1::allocate<asn1::SequenceOfPsidSsp>();
        m_struct->toBeSigned.appPermissions = seq;
    }
    // Allocate the memory
    auto psid_ptr = asn1::allocate<asn1::PsidSsp>();
    psid_ptr->psid = aid;
    psid_ptr->ssp = asn1::allocate<asn1::ServiceSpecificPermissions>();
    psid_ptr->ssp->present = Vanetza_Security_ServiceSpecificPermissions_PR_opaque;
    OCTET_STRING_fromBuf(
        &(psid_ptr->ssp->choice.opaque),
        reinterpret_cast<const char *>(ssp.data()),
        ssp.size()
    );
    ASN_SEQUENCE_ADD(seq, psid_ptr);

}

void Certificate::add_cert_permission(asn1::PsidGroupPermissions* group_permission)
{
    asn1::SequenceOfPsidGroupPermissions* seq = m_struct->toBeSigned.certIssuePermissions;
    if (!seq) {
        seq = asn1::allocate<asn1::SequenceOfPsidGroupPermissions>();
        m_struct->toBeSigned.certIssuePermissions = seq;
    }
    ASN_SEQUENCE_ADD(seq, group_permission);
}

void Certificate::set_signature(const SomeEcdsaSignature& signature)
{
    struct ecc_point_visitor : public boost::static_visitor<asn1::EccP256CurvePoint>
    {
        asn1::EccP256CurvePoint operator()(const X_Coordinate_Only& x_only) const
        {
            auto to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
            OCTET_STRING_fromBuf(
                &(to_return->choice.x_only),
                reinterpret_cast<const char*>(x_only.x.data()),
                x_only.x.size()
            );
            return *to_return;
        }

        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_0& y0) const
        {
            auto to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_0),
                reinterpret_cast<const char*>(y0.x.data()),
                y0.x.size()
            );
            return *to_return;
        }

        asn1::EccP256CurvePoint operator()(const Compressed_Lsb_Y_1& y1) const
        {
            auto to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_1),
                reinterpret_cast<const char*>(y1.x.data()),
                y1.x.size()
            );
            return *to_return;
        }

        asn1::EccP256CurvePoint operator()(const Uncompressed& unc) const
        {
            auto to_return = asn1::allocate<asn1::EccP256CurvePoint>();
            to_return->present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
            OCTET_STRING_fromBuf(
                &(to_return->choice.uncompressedP256.x),
                reinterpret_cast<const char*>(unc.x.data()),
                unc.x.size()
            );
            OCTET_STRING_fromBuf(
                &(to_return->choice.uncompressedP256.y),
                reinterpret_cast<const char*>(unc.y.data()),
                unc.y.size()
            );
            return *to_return;
        }
    };

    struct signature_visitor : public boost::static_visitor<asn1::Signature*>
    {
        asn1::Signature* operator()(const EcdsaSignature& signature) const
        {
            auto final_signature = asn1::allocate<asn1::Signature>();
            final_signature->present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            OCTET_STRING_fromBuf(
                &(final_signature->choice.ecdsaNistP256Signature.sSig),
                reinterpret_cast<const char*>(signature.s.data()),
                signature.s.size()
            );
            final_signature->choice.ecdsaNistP256Signature.rSig = boost::apply_visitor(
                ecc_point_visitor(),
                signature.R
            );
            return final_signature;
        }

        asn1::Signature* operator()(const EcdsaSignatureFuture& signature) const
        {
            return this->operator()(signature.get());
        }
    };

    m_struct->signature = boost::apply_visitor(signature_visitor(), signature);
}

Certificate fake_certificate()
{
    Certificate certi;
    certi->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
    certi->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    std::vector<uint8_t> craciId(3, 0); // Correct length for P256 signature part
    OCTET_STRING_fromBuf(
        &certi->toBeSigned.cracaId,
        reinterpret_cast<const char*>(craciId.data()),
        craciId.size()
    );
    certi->version = 3;
    certi->toBeSigned.crlSeries = 0;
    certi->toBeSigned.validityPeriod.start = 0;
    certi->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_minutes;
    certi->toBeSigned.validityPeriod.duration.choice.minutes = 10080;
    certi->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    certi->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    certi->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    std::vector<uint8_t> dummy_r(32, 0); // Correct length for P256 signature part
    dummy_r[0] = 0; // Ensure the leading byte is set to zero if needed
    OCTET_STRING_fromBuf(
        &certi->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.choice.x_only,
        reinterpret_cast<const char*>(dummy_r.data()),
        dummy_r.size()
    );
    certi.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    return certi;
}

void serialize(OutputArchive& ar, Certificate& certificate)
{
    ByteBuffer buffer = certificate.encode();
    ar.save_binary(buffer.data(), buffer.size());
}

namespace
{

bool copy_curve_point(PublicKey& to, const asn1::EccP256CurvePoint& from)
{
    bool copied = true;
    switch (from.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            to.compression = KeyCompression::Y0;
            to.x = fetch_octets(from.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            to.compression = KeyCompression::Y1;
            to.x = fetch_octets(from.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
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

bool copy_curve_point(PublicKey& to, const asn1::EccP384CurvePoint& from)
{
    bool copied = true;
    switch (from.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
            to.compression = KeyCompression::Y0;
            to.x = fetch_octets(from.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            to.compression = KeyCompression::Y1;
            to.x = fetch_octets(from.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384:
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

bool is_compressed(const Vanetza_Security_EccP256CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            return true;
        default:
            return false;
    }
}

bool is_compressed(const Vanetza_Security_EccP384CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            return true;
        default:
            return false;
    }
}

bool is_signature_x_only(const Vanetza_Security_Signature_t& sig)
{
    switch (sig.present) {
        case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
            return sig.choice.ecdsaNistP256Signature.rSig.present == Vanetza_Security_EccP256CurvePoint_PR_x_only;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
            return sig.choice.ecdsaBrainpoolP256r1Signature.rSig.present == Vanetza_Security_EccP256CurvePoint_PR_x_only;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            return sig.choice.ecdsaBrainpoolP384r1Signature.rSig.present == Vanetza_Security_EccP384CurvePoint_PR_x_only;
        default:
            return true; // not an ECDSA signature at all
    }
}

bool compress(Vanetza_Security_EccP256CurvePoint& point)
{
    if (point.present == Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256) {
        auto& unc = point.choice.uncompressedP256;
        if (unc.y.size > 0 && unc.y.buf[unc.y.size - 1] & 0x01) {
            assert(&point.choice.uncompressedP256.x == &point.choice.compressed_y_1);
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
        } else {
            assert(&point.choice.uncompressedP256.x == &point.choice.compressed_y_0);
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
        }
        return true;
    } else if (point.present == Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0 || point.present == Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1) {
        return true;
    } else {
        return false;
    }
}

bool compress(Vanetza_Security_EccP384CurvePoint& point)
{
    if (point.present == Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384) {
        auto& unc = point.choice.uncompressedP384;
        if (unc.y.size > 0 && unc.y.buf[unc.y.size - 1] & 0x01) {
            assert(&point.choice.uncompressedP384.x == &point.choice.compressed_y_1);
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1;
        } else {
            assert(&point.choice.uncompressedP384.x == &point.choice.compressed_y_0);
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0;
        }
        return true;
    } else if (point.present == Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0 || point.present == Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1) {
        return true;
    } else {
        return false;
    }
}

bool make_x_only(Vanetza_Security_EccP256CurvePoint& point)
{
    if (point.present == Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256) {
        assert(&point.choice.uncompressedP256.x == &point.choice.x_only);
        point.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
        return true;
    } else if (point.present == Vanetza_Security_EccP256CurvePoint_PR_x_only) {
        return true;
    } else {
        return false;
    }
}

bool make_x_only(Vanetza_Security_EccP384CurvePoint& point)
{
    if (point.present == Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384) {
        assert(&point.choice.uncompressedP384.x == &point.choice.x_only);
        point.present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
        return true;
    } else if (point.present == Vanetza_Security_EccP384CurvePoint_PR_x_only) {
        return true;
    } else {
        return false;
    }
}

bool make_signature_x_only(Vanetza_Security_Signature& sig)
{
    switch (sig.present) {
        case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
            return make_x_only(sig.choice.ecdsaNistP256Signature.rSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
            return make_x_only(sig.choice.ecdsaBrainpoolP256r1Signature.rSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            return make_x_only(sig.choice.ecdsaBrainpoolP384r1Signature.rSig);
            break;
        default:
            return false;
            break;
    }
}

} // namespace

} // namespace v3
} // namespace security
} // namespace vanetza
