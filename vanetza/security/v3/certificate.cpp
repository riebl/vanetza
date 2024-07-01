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

void add_psid_group_permission(PsidGroupPermissions* group_permission, ItsAid aid, const ByteBuffer& ssp, const ByteBuffer& bitmask){
    PsidSspRange* psid_range_scr = static_cast<PsidSspRange*>(vanetza::asn1::allocate(sizeof(PsidSspRange)));
    psid_range_scr->psid = aid;
    psid_range_scr->sspRange = static_cast<SspRange*>(vanetza::asn1::allocate(sizeof(SspRange)));
    psid_range_scr->sspRange->present = SspRange_PR_bitmapSspRange;
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

void add_app_permissions(Certificate& cert, ItsAid aid) {
    SequenceOfPsidSsp_t* seq = cert->toBeSigned.appPermissions;
    if (!seq) {
        seq = static_cast<SequenceOfPsidSsp_t*>(vanetza::asn1::allocate(sizeof(SequenceOfPsidSsp_t)));
        cert->toBeSigned.appPermissions = seq;
    }
    // Allocate the memory
    PsidSsp* psid_ptr = static_cast<PsidSsp*>(vanetza::asn1::allocate(sizeof(PsidSsp)));
    psid_ptr->psid = aid;
    ASN_SEQUENCE_ADD(seq, psid_ptr);
}

void Certificate::add_permission(ItsAid aid, const ByteBuffer& ssp){
    SequenceOfPsidSsp_t* seq = m_struct->toBeSigned.appPermissions;
    if (!seq) {
        seq = static_cast<SequenceOfPsidSsp_t*>(vanetza::asn1::allocate(sizeof(SequenceOfPsidSsp_t)));
        m_struct->toBeSigned.appPermissions = seq;
    }
    // Allocate the memory
    PsidSsp* psid_ptr = static_cast<PsidSsp*>(vanetza::asn1::allocate(sizeof(PsidSsp)));
    psid_ptr->psid = aid;
    psid_ptr->ssp = static_cast<ServiceSpecificPermissions*>(vanetza::asn1::allocate(sizeof(ServiceSpecificPermissions)));
    psid_ptr->ssp->present = ServiceSpecificPermissions_PR_opaque;
    OCTET_STRING_fromBuf(
        &(psid_ptr->ssp->choice.opaque),
        reinterpret_cast<const char *>(ssp.data()),
        ssp.size()
    );
    ASN_SEQUENCE_ADD(seq, psid_ptr);

}

void Certificate::add_cert_permission(PsidGroupPermissions* group_permission){
    SequenceOfPsidGroupPermissions* seq = m_struct->toBeSigned.certIssuePermissions;
    if (!seq) {
        seq = static_cast<SequenceOfPsidGroupPermissions*>(vanetza::asn1::allocate(sizeof(SequenceOfPsidGroupPermissions)));
        m_struct->toBeSigned.certIssuePermissions = seq;
    }
    ASN_SEQUENCE_ADD(seq, group_permission);
}

void Certificate::set_signature(const SomeEcdsaSignature& signature) {
    struct ecc_point_visitor : public boost::static_visitor<EccP256CurvePoint_t> {
        EccP256CurvePoint_t operator()(const X_Coordinate_Only& x_only) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_x_only;
            OCTET_STRING_fromBuf(
                &(to_return->choice.x_only),
                reinterpret_cast<const char*>(x_only.x.data()),
                x_only.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_0& y0) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_compressed_y_0;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_0),
                reinterpret_cast<const char*>(y0.x.data()),
                y0.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Compressed_Lsb_Y_1& y1) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_compressed_y_1;
            OCTET_STRING_fromBuf(
                &(to_return->choice.compressed_y_1),
                reinterpret_cast<const char*>(y1.x.data()),
                y1.x.size()
            );
            return *to_return;
        }
        EccP256CurvePoint_t operator()(const Uncompressed& unc) const
        {
            EccP256CurvePoint_t* to_return = static_cast<EccP256CurvePoint_t*>(vanetza::asn1::allocate(sizeof(EccP256CurvePoint_t)));
            to_return->present = EccP256CurvePoint_PR_uncompressedP256;
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
    struct signature_visitor : public boost::static_visitor<Signature_t*>
    {
        Signature_t* operator()(const EcdsaSignature& signature) const
        {
            Signature_t* final_signature = static_cast<Signature_t*>(vanetza::asn1::allocate(sizeof(Signature_t)));
            final_signature->present = Signature_PR_ecdsaNistP256Signature;
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
        Signature_t* operator()(const EcdsaSignatureFuture& signature) const
        {
            Signature_t* final_signature = static_cast<Signature_t*>(vanetza::asn1::allocate(sizeof(Signature_t)));
/*             EcdsaSignature temp = signature.get();
            final_signature = boost::apply_visitor(signature_visitor(), temp); */
            return final_signature;
        }
    };
    m_struct->signature = (boost::apply_visitor(signature_visitor(), signature));
}

ByteBuffer Certificate::serialize() {
    return this->encode();
}

ByteBuffer Certificate::convert_for_signing(){
    vanetza::ByteBuffer to_return;
    try{
        to_return = vanetza::asn1::encode_oer(asn_DEF_EtsiTs103097Certificate, m_struct);
    }catch(std::runtime_error& er){
    }
    return to_return;
}

Certificate fake_certificate() {

    Certificate certi;
    certi->issuer.present = IssuerIdentifier_PR_self;
    certi->toBeSigned.id.present = CertificateId_PR_none;
    std::vector<uint8_t> craciId(3, 0); // Correct length for P256 signature part
    OCTET_STRING_fromBuf(
        &certi->toBeSigned.cracaId,
        reinterpret_cast<const char*>(craciId.data()),
        craciId.size()
    );
    certi->version = 3;
    certi->toBeSigned.crlSeries = 0;
    certi->toBeSigned.validityPeriod.start = 0;
    certi->toBeSigned.validityPeriod.duration.present = Duration_PR_minutes;
    certi->toBeSigned.validityPeriod.duration.choice.minutes = 10080;
    certi->toBeSigned.verifyKeyIndicator.present = VerificationKeyIndicator_PR_verificationKey;
    certi->toBeSigned.verifyKeyIndicator.choice.verificationKey.present = PublicVerificationKey_PR_ecdsaNistP256;
    certi->toBeSigned.verifyKeyIndicator.choice.verificationKey.choice.ecdsaNistP256.present = EccP256CurvePoint_PR_x_only;
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

void serialize(OutputArchive& ar, Certificate& certificate) {
    vanetza::ByteBuffer buffer = certificate.serialize();
    for (auto& temp_byte : buffer){
        ar << temp_byte;
    }
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
