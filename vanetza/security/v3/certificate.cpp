#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/security/sha.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/distance.hpp>
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
ByteBuffer get_x_coordinate(const asn1::EccP256CurvePoint& point);
ByteBuffer get_x_coordinate(const asn1::EccP384CurvePoint& point);

bool is_compressed(const Vanetza_Security_EccP256CurvePoint& point);
bool is_compressed(const Vanetza_Security_EccP384CurvePoint& point);
bool is_signature_x_only(const Vanetza_Security_Signature_t& sig);
bool compress(Vanetza_Security_EccP256CurvePoint&);
bool compress(Vanetza_Security_EccP384CurvePoint&);
bool make_x_only(Vanetza_Security_EccP256CurvePoint&);
bool make_x_only(Vanetza_Security_EccP384CurvePoint&);
bool make_signature_x_only(Vanetza_Security_Signature_t& sig);

} // namespace

CertificateView::CertificateView(const asn1::EtsiTs103097Certificate* cert) :
    m_cert(cert)
{
}

Certificate::Certificate() :
    Wrapper(asn_DEF_Vanetza_Security_EtsiTs103097Certificate),
    CertificateView { content() }
{
    assert(CertificateView::m_cert == Wrapper::m_struct);
}

Certificate::Certificate(const asn1::EtsiTs103097Certificate& cert) :
    Wrapper(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &cert),
    CertificateView { content() }
{
    assert(CertificateView::m_cert == Wrapper::m_struct);
}

Certificate::Certificate(const Certificate& other) :
    Wrapper(other), CertificateView(content())
{
    assert(CertificateView::m_cert == Wrapper::m_struct);
}

Certificate& Certificate::operator=(const Certificate& other)
{
    Wrapper::operator=(other);
    CertificateView::m_cert = content();
    assert(CertificateView::m_cert == Wrapper::m_struct);
    return *this;
}

Certificate::Certificate(Certificate&& other) :
    Wrapper(std::move(other)), CertificateView(content())
{
    assert(CertificateView::m_cert == Wrapper::m_struct);
}

Certificate& Certificate::operator=(Certificate&& other)
{
    Wrapper::operator=(std::move(other));
    CertificateView::m_cert = content();
    assert(CertificateView::m_cert == Wrapper::m_struct);
    return *this;
}

boost::optional<HashedId8> CertificateView::calculate_digest() const
{
    return m_cert ? v3::calculate_digest(*m_cert) : boost::none;
}

KeyType CertificateView::get_verification_key_type() const
{
    return m_cert ? v3::get_verification_key_type(*m_cert) : KeyType::Unspecified;
}

bool CertificateView::valid_at_location(const PositionFix& location, const LocationChecker* lc) const
{
    return m_cert ? lc ? lc->valid_at_location(*m_cert, location) : false :  false;
}

bool CertificateView::valid_at_timepoint(const Clock::time_point& timepoint) const
{
    return m_cert ? v3::valid_at_timepoint(*m_cert, timepoint) : false;
}

bool valid_at_timepoint(const asn1::EtsiTs103097Certificate& cert, const Clock::time_point& timepoint)
{
    const asn1::ValidityPeriod& validity = cert.toBeSigned.validityPeriod;
    Clock::time_point start { std::chrono::seconds(validity.start) };
    Clock::time_point end = start;

    switch (validity.duration.present)
    {
        case Vanetza_Security_Duration_PR_microseconds:
            end += std::chrono::microseconds(validity.duration.choice.microseconds);
            break;
        case Vanetza_Security_Duration_PR_milliseconds:
            end += std::chrono::milliseconds(validity.duration.choice.milliseconds);
            break;
        case Vanetza_Security_Duration_PR_seconds:
            end += std::chrono::seconds(validity.duration.choice.seconds);
            break;
        case Vanetza_Security_Duration_PR_minutes:
            end += std::chrono::minutes(validity.duration.choice.minutes);
            break;
        case Vanetza_Security_Duration_PR_hours:
            end += std::chrono::hours(validity.duration.choice.hours);
            break;
        case Vanetza_Security_Duration_PR_sixtyHours:
            end += std::chrono::hours(60) * validity.duration.choice.sixtyHours;
            break;
        case Vanetza_Security_Duration_PR_years:
            // one year is considered 31556952 seconds according to IEEE 1609.2
            end += std::chrono::seconds(31556952) * validity.duration.choice.years;
            break;
        default:
            // leave end at start and thus forming an invalid range
            break;
    }
    
    return timepoint >= start && timepoint < end;
}

bool CertificateView::valid_for_application(ItsAid aid) const
{
    return m_cert ? v3::valid_for_application(*m_cert, aid) : false;
}

bool valid_for_application(const asn1::EtsiTs103097Certificate& cert, ItsAid aid)
{
    const asn1::SequenceOfPsidSsp* permissions = cert.toBeSigned.appPermissions;
    if (permissions) {
        for (int i = 0; i < permissions->list.count; ++i) {
            if (permissions->list.array[i]->psid == aid) {
                return true;
            }
        }
    }

    // only explicitly allowed applications are valid
    return false;
}

boost::optional<HashedId8> CertificateView::issuer_digest() const
{
    boost::optional<HashedId8> digest;
    if (m_cert != nullptr) {
        switch (m_cert->issuer.present)
        {
            case Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest:
                digest = create_hashed_id8(m_cert->issuer.choice.sha256AndDigest);
                break;
            case Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest:
                digest = create_hashed_id8(m_cert->issuer.choice.sha384AndDigest);
                break;
            default:
                break;
        }
    }
    return digest;
}

bool CertificateView::issuer_is_self() const
{
    return m_cert->issuer.present == Vanetza_Security_IssuerIdentifier_PR_self;
}

bool CertificateView::has_region_restriction() const
{
    return m_cert ? m_cert->toBeSigned.region != nullptr : false;
}

bool CertificateView::is_ca_certificate() const
{
    return m_cert && m_cert->toBeSigned.certIssuePermissions != nullptr;
}

bool CertificateView::is_at_certificate() const
{
    return m_cert && m_cert->toBeSigned.certIssuePermissions == nullptr && m_cert->toBeSigned.appPermissions != nullptr;
}

bool CertificateView::is_canonical() const
{
    return m_cert ? v3::is_canonical(*m_cert) : false;
}

StartAndEndValidity CertificateView::get_start_and_end_validity() const
{
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = Time32(m_cert->toBeSigned.validityPeriod.start);
    Time32 duration = 0;
    switch (m_cert->toBeSigned.validityPeriod.duration.present)
    {
    case Vanetza_Security_Duration_PR_NOTHING:
        break;
    case Vanetza_Security_Duration_PR_microseconds:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.microseconds/1000000;
        break;
    case Vanetza_Security_Duration_PR_milliseconds:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.milliseconds/1000;
        break;
    case Vanetza_Security_Duration_PR_seconds:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.seconds;
        break;
    case Vanetza_Security_Duration_PR_minutes:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.minutes*60;
        break;
    case Vanetza_Security_Duration_PR_hours:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.hours*60*60;
        break;
    case Vanetza_Security_Duration_PR_sixtyHours:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.sixtyHours*60*60*60;
        break;
    case Vanetza_Security_Duration_PR_years:
        duration += (int)m_cert->toBeSigned.validityPeriod.duration.choice.years*60*60*24*365;
        break;
    default:
        break;
    }
    start_and_end.end_validity = start_and_end.start_validity + duration;
    return start_and_end;
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

ByteBuffer CertificateView::encode() const
{
    return m_cert ? asn1::encode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, m_cert) : ByteBuffer {};
}

ByteBuffer Certificate::encode() const
{
    return Wrapper::encode();
}

boost::optional<Certificate> CertificateView::canonicalize() const
{
    return m_cert ? v3::canonicalize(*m_cert) : boost::none;
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

    if (canonical->toBeSigned.encryptionKey) {
        Vanetza_Security_BasePublicEncryptionKey& pubkey = canonical->toBeSigned.encryptionKey->publicKey;
        switch (pubkey.present) {
            case Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256:
                success &= compress(pubkey.choice.eciesNistP256);
                break;
            case Vanetza_Security_BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
                success &= compress(pubkey.choice.eciesBrainpoolP256r1);
                break;
            default:
                break;
        }
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

boost::optional<PublicKey> get_public_encryption_key(const asn1::EtsiTs103097Certificate& cert)
{
    const asn1::PublicEncryptionKey* enc_key = cert.toBeSigned.encryptionKey;
    if (!enc_key || enc_key->supportedSymmAlg != Vanetza_Security_SymmAlgorithm_aes128Ccm) {
        return boost::none;
    }

    PublicKey output;
    switch (enc_key->publicKey.present) {
        case Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256:
            output.type = KeyType::NistP256;
            if (copy_curve_point(output, enc_key->publicKey.choice.eciesNistP256)) {
                return output;
            } else {
                return boost::none;
            }
            break;
        case Vanetza_Security_BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
            output.type = KeyType::BrainpoolP256r1;
            if (copy_curve_point(output, enc_key->publicKey.choice.eciesBrainpoolP256r1)) {
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

boost::optional<Signature> get_signature(const asn1::EtsiTs103097Certificate& cert)
{
    if (!cert.signature) {
        return boost::none;
    }

    const asn1::Signature* asn = cert.signature;
    Signature sig;
    switch (asn->present) {
        case Vanetza_Security_Signature_PR_ecdsaNistP256Signature:
            sig.type = KeyType::NistP256;
            sig.r = get_x_coordinate(asn->choice.ecdsaNistP256Signature.rSig);
            sig.s = fetch_octets(asn->choice.ecdsaNistP256Signature.sSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature:
            sig.type = KeyType::BrainpoolP256r1;
            sig.r = get_x_coordinate(asn->choice.ecdsaBrainpoolP256r1Signature.rSig);
            sig.s = fetch_octets(asn->choice.ecdsaBrainpoolP256r1Signature.sSig);
            break;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            sig.type = KeyType::BrainpoolP384r1;
            sig.r = get_x_coordinate(asn->choice.ecdsaBrainpoolP384r1Signature.rSig);
            sig.s = fetch_octets(asn->choice.ecdsaBrainpoolP384r1Signature.sSig);
            break;
        default:
            return boost::none;
    }

    return sig;
}

std::list<ItsAid> get_aids(const asn1::EtsiTs103097Certificate& cert)
{
    std::list<ItsAid> aids;
    const asn1::SequenceOfPsidSsp* seq = cert.toBeSigned.appPermissions;
    if (seq) {
        for (int i = 0; i < seq->list.count; ++i) {
            aids.push_back(seq->list.array[i]->psid);
        }
    }
    return aids;
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
            final_signature->choice.ecdsaNistP256Signature.rSig = to_asn1(signature.R);
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

void serialize(OutputArchive& ar, const Certificate& certificate)
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

ByteBuffer get_x_coordinate(const asn1::EccP256CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            return fetch_octets(point.choice.compressed_y_0);
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            return fetch_octets(point.choice.compressed_y_1);
        case Vanetza_Security_EccP256CurvePoint_PR_x_only:
            return fetch_octets(point.choice.x_only);
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            return fetch_octets(point.choice.uncompressedP256.x);
        default:
            return ByteBuffer {};
    }
}

ByteBuffer get_x_coordinate(const asn1::EccP384CurvePoint& point)
{
    switch (point.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
            return fetch_octets(point.choice.compressed_y_0);
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            return fetch_octets(point.choice.compressed_y_1);
        case Vanetza_Security_EccP384CurvePoint_PR_x_only:
            return fetch_octets(point.choice.x_only);
        case Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384:
            return fetch_octets(point.choice.uncompressedP384.x);
        default:
            return ByteBuffer {};
    }
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
