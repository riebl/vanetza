#include "certificate.hpp"
#include "asn1.hpp"
#include "security_module.hpp"
#include <vanetza/common/its_aid.hpp>

namespace vanetza
{
namespace pki
{

namespace
{

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
            return sig.choice.ecdsaBrainpoolP256r1Signature.rSig.present ==
                   Vanetza_Security_EccP256CurvePoint_PR_x_only;
        case Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature:
            return sig.choice.ecdsaBrainpoolP384r1Signature.rSig.present ==
                   Vanetza_Security_EccP384CurvePoint_PR_x_only;
        default:
            return true; // not an ECDSA signature at all
    }
}

void copy_coordinates(const Vanetza_Security_EccP256CurvePoint_t& point, PublicKey& key)
{
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            key.compression = KeyCompression::NoCompression;
            pki::copy(point.choice.uncompressedP256.x, key.x);
            pki::copy(point.choice.uncompressedP256.y, key.y);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            key.compression = KeyCompression::Y0;
            pki::copy(point.choice.compressed_y_0, key.x);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            key.compression = KeyCompression::Y1;
            pki::copy(point.choice.compressed_y_1, key.x);
            break;
        default:
            throw std::runtime_error("unsupported curve point type");
            break;
    }
}

template<KeyType> PublicKey make_public_key(const Vanetza_Security_EccP256CurvePoint_t& point);

template<> PublicKey make_public_key<KeyType::NistP256>(const Vanetza_Security_EccP256CurvePoint_t& point)
{
    PublicKey pub;
    pub.type = KeyType::NistP256;
    copy_coordinates(point, pub);
    return pub;
}

template<> PublicKey make_public_key<KeyType::BrainpoolP256r1>(const Vanetza_Security_EccP256CurvePoint_t& point)
{
    PublicKey pub;
    pub.type = KeyType::BrainpoolP256r1;
    copy_coordinates(point, pub);
    return pub;
}

} // namespace

Certificate::Certificate() : m_asn1(asn_DEF_Vanetza_Security_EtsiTs103097Certificate)
{
}

Certificate::Certificate(const Vanetza_Security_EtsiTs103097Certificate_t& src) :
    m_asn1(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &src)
{
}

std::string Certificate::get_name() const
{
    return pki::get_name(*m_asn1);
}

PublicKey Certificate::get_public_key() const
{
    return pki::get_public_key(*m_asn1);
}

boost::optional<PublicKey> Certificate::get_encryption_key() const
{
    if (m_asn1->toBeSigned.encryptionKey) {
        const Vanetza_Security_PublicEncryptionKey_t& enckey = *m_asn1->toBeSigned.encryptionKey;
        switch (enckey.publicKey.present) {
            case Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256:
                return make_public_key<KeyType::NistP256>(enckey.publicKey.choice.eciesNistP256);
                break;
            case Vanetza_Security_BasePublicEncryptionKey_PR_eciesBrainpoolP256r1:
                return make_public_key<KeyType::BrainpoolP256r1>(enckey.publicKey.choice.eciesBrainpoolP256r1);
                break;
            default:
                throw std::runtime_error("unsupported encryption key type");
                break;
        }
    } else {
        return boost::none;
    }
}

Clock::time_point Certificate::valid_since() const
{
    return Clock::time_point { std::chrono::seconds(m_asn1->toBeSigned.validityPeriod.start) };
}

Clock::time_point Certificate::valid_until() const
{
    Clock::duration d;
    const Vanetza_Security_Duration& asn1_d = m_asn1->toBeSigned.validityPeriod.duration;
    switch (asn1_d.present) {
        case Vanetza_Security_Duration_PR_years:
            // IEEE 1609.2: "A year is considered to be 31556952 seconds"
            d = asn1_d.choice.years * std::chrono::seconds(31556952);
            break;
        case Vanetza_Security_Duration_PR_sixtyHours:
            d = std::chrono::hours(60 * asn1_d.choice.sixtyHours);
            break;
        case Vanetza_Security_Duration_PR_hours:
            d = std::chrono::hours(asn1_d.choice.hours);
            break;
        case Vanetza_Security_Duration_PR_minutes:
            d = std::chrono::minutes(asn1_d.choice.minutes);
            break;
        case Vanetza_Security_Duration_PR_seconds:
            d = std::chrono::seconds(asn1_d.choice.seconds);
            break;
        case Vanetza_Security_Duration_PR_milliseconds:
            d = std::chrono::milliseconds(asn1_d.choice.milliseconds);
            break;
        case Vanetza_Security_Duration_PR_microseconds:
            d = std::chrono::microseconds(asn1_d.choice.microseconds);
            break;
        default:
            // no validity duration as safe fallback
            d = std::chrono::seconds(0);
            break;
    }
    return valid_since() + d;
}

bool Certificate::decode(const char* data, std::size_t length)
{
    return m_asn1.decode(data, length);
}

bool Certificate::decode(const std::string& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

bool Certificate::decode(const ByteBuffer& buffer)
{
    return m_asn1.decode(buffer.data(), buffer.size());
}

ByteBuffer Certificate::encode() const
{
    return m_asn1.encode();
}

void Certificate::print() const
{
    xer_fprint(stdout, &asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &*m_asn1);
}

bool Certificate::is_canonical() const
{
    return vanetza::pki::is_canonical(*m_asn1);
}

HashedId8 Certificate::calculate_hashed_id8(SecurityModule& sec) const
{
    return vanetza::pki::calculate_hashed_id8(sec, *m_asn1);
}

Sha256Hash calculate_sha256_hash(SecurityModule& sec, const Certificate& cert)
{
    ByteBuffer buffer = cert.encode();
    return sec.calculate_sha256_hash(buffer.data(), buffer.size());
}

Sha384Hash calculate_sha384_hash(SecurityModule& sec, const Certificate& cert)
{
    ByteBuffer buffer = cert.encode();
    return sec.calculate_sha384_hash(buffer.data(), buffer.size());
}

bool is_currently_valid(const Certificate& cert, Clock::time_point t)
{
    return cert.valid_since() <= t && cert.valid_until() >= t;
}

bool is_root_ca(const Certificate& cert)
{
    const auto& issuer = cert.raw().issuer;
    const bool self_issued = (issuer.present == Vanetza_Security_IssuerIdentifier_PR_self);
    if (!self_issued) {
        return false;
    }

    const auto& tbs = cert.raw().toBeSigned;
    const bool can_issue = tbs.certIssuePermissions && tbs.certIssuePermissions->list.count > 0;
    if (!can_issue) {
        return false;
    }

    if (tbs.appPermissions) {
        bool sign_crl = false;
        bool sign_ctl = false;

        for (int i = 0; i < tbs.appPermissions->list.count; ++i) {
            const Vanetza_Security_PsidSsp_t* permission = tbs.appPermissions->list.array[i];
            if (!permission) {
                continue;
            }
            switch (permission->psid) {
                case aid::CTL:
                    sign_ctl = true;
                    break;

                case aid::CRL:
                    sign_crl = true;
                    break;

                default:
                    // no op
                    break;
            }
        }

        if (!sign_ctl || !sign_crl) {
            return false;
        }
    } else {
        return false;
    }

    return true;
}

namespace
{

bool issuing_scope_contains(const Certificate& cert, ItsAid target)
{
    const auto* cip = cert.raw().toBeSigned.certIssuePermissions;
    if (!cip) {
        return false;
    }
    for (int i = 0; i < cip->list.count; ++i) {
        const auto* group = cip->list.array[i];
        if (!group) {
            continue;
        }
        const auto& sp = group->subjectPermissions;
        if (sp.present == Vanetza_Security_SubjectPermissions_PR_all) {
            return true;
        }
        if (sp.present == Vanetza_Security_SubjectPermissions_PR_explicit) {
            const auto& ranges = sp.choice.Explicit.list;
            for (int j = 0; j < ranges.count; ++j) {
                if (ranges.array[j] && ranges.array[j]->psid == static_cast<long>(target)) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool app_permissions_contains(const Certificate& cert, ItsAid target)
{
    const auto* ap = cert.raw().toBeSigned.appPermissions;
    if (!ap) {
        return false;
    }
    for (int i = 0; i < ap->list.count; ++i) {
        if (ap->list.array[i] && ap->list.array[i]->psid == static_cast<long>(target)) {
            return true;
        }
    }
    return false;
}

} // namespace

CertificateRole certificate_role(const Certificate& cert)
{
    if (is_root_ca(cert)) {
        return CertificateRole::RootCa;
    }

    const auto& tbs = cert.raw().toBeSigned;
    const bool self_issued = (cert.raw().issuer.present == Vanetza_Security_IssuerIdentifier_PR_self);
    const bool has_cert_issue = tbs.certIssuePermissions && tbs.certIssuePermissions->list.count > 0;

    if (self_issued) {
        // TS 103 097 §7.2.5: TLM is self-signed, signs the CTL, no certIssuePermissions.
        if (!has_cert_issue && app_permissions_contains(cert, aid::CTL)) {
            return CertificateRole::Tlm;
        }
        return CertificateRole::Unknown;
    }

    if (has_cert_issue) {
        // TS 103 097 §7.2.4 subordinate CA. Per TS 102 941 Table 1 the EA issues
        // enrolment credentials (SCR in scope); the AA issues authorization tickets.
        return issuing_scope_contains(cert, aid::SCR) ? CertificateRole::EnrolmentAuthority :
                                                        CertificateRole::AuthorizationAuthority;
    }

    // End entity: §7.2.2 EC uses CertificateId name, §7.2.1 AT uses CertificateId none.
    switch (tbs.id.present) {
        case Vanetza_Security_CertificateId_PR_name:
            return CertificateRole::EnrolmentCredential;
        case Vanetza_Security_CertificateId_PR_none:
            return CertificateRole::AuthorizationTicket;
        default:
            return CertificateRole::Unknown;
    }
}

bool is_canonical(const Vanetza_Security_EtsiTs103097Certificate_t& cert)
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

Sha256Hash calculate_sha256_hash(SecurityModule& security, const Vanetza_Security_Certificate_t& cert)
{
    ByteBuffer buffer = asn1::encode_oer(asn_DEF_Vanetza_Security_Certificate, &cert);
    return security.calculate_sha256_hash(buffer.data(), buffer.size());
}

Sha384Hash calculate_sha384_hash(SecurityModule& sec, const Vanetza_Security_Certificate_t& cert)
{
    ByteBuffer buffer = asn1::encode_oer(asn_DEF_Vanetza_Security_Certificate, &cert);
    return sec.calculate_sha384_hash(buffer.data(), buffer.size());
}

HashedId8 calculate_hashed_id8(SecurityModule& sec, const Vanetza_Security_Certificate_t& cert)
{
    if (!is_canonical(cert)) {
        throw std::runtime_error("HashedId8 can only be calculated for canonical certificates");
    }

    // all explicit certificates possess an verification key
    const Vanetza_Security_VerificationKeyIndicator& indicator = cert.toBeSigned.verifyKeyIndicator;
    if (indicator.present == Vanetza_Security_VerificationKeyIndicator_PR_verificationKey) {
        switch (indicator.choice.verificationKey.present) {
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
                return HashedId8 { calculate_sha256_hash(sec, cert) };
            case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
                return HashedId8 { calculate_sha384_hash(sec, cert) };
            default:
                throw std::runtime_error("do not know how to hash the certificate");
                break;
        }
    } else {
        // fall back to SHA-256
        return HashedId8 { calculate_sha256_hash(sec, cert) };
    }
}

PublicKey make_public_key(KeyType t, const Vanetza_Security_EccP256CurvePoint_t& point)
{
    PublicKey pub;
    pub.type = t;
    switch (point.present) {
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0:
            pub.compression = KeyCompression::Y0;
            pub.x = copy(point.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1:
            pub.compression = KeyCompression::Y1;
            pub.x = copy(point.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256:
            pub.compression = KeyCompression::NoCompression;
            pub.x = copy(point.choice.uncompressedP256.x);
            pub.y = copy(point.choice.uncompressedP256.y);
            break;
        default:
            throw std::runtime_error("cannot create public key from given curve point");
            break;
    }
    return pub;
}

PublicKey make_public_key(KeyType t, const Vanetza_Security_EccP384CurvePoint_t& point)
{
    PublicKey pub;
    pub.type = t;
    switch (point.present) {
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0:
            pub.compression = KeyCompression::Y0;
            pub.x = copy(point.choice.compressed_y_0);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1:
            pub.compression = KeyCompression::Y1;
            pub.x = copy(point.choice.compressed_y_1);
            break;
        case Vanetza_Security_EccP384CurvePoint_PR_uncompressedP384:
            pub.compression = KeyCompression::NoCompression;
            pub.x = copy(point.choice.uncompressedP384.x);
            pub.y = copy(point.choice.uncompressedP384.y);
            break;
        default:
            throw std::runtime_error("cannot create public key from given curve point");
            break;
    }
    return pub;
}

PublicKey get_public_key(const Vanetza_Security_PublicVerificationKey_t& input)
{
    switch (input.present) {
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256:
            return make_public_key(KeyType::NistP256, input.choice.ecdsaNistP256);
            break;
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1:
            return make_public_key(KeyType::BrainpoolP256r1, input.choice.ecdsaBrainpoolP256r1);
            break;
        case Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1:
            return make_public_key(KeyType::BrainpoolP384r1, input.choice.ecdsaBrainpoolP384r1);
            break;
        default:
            throw std::runtime_error("unknown public verification key type");
            break;
    }
}

PublicKey get_public_key(const Vanetza_Security_Certificate_t& cert)
{
    switch (cert.toBeSigned.verifyKeyIndicator.present) {
        case Vanetza_Security_VerificationKeyIndicator_PR_verificationKey:
            return get_public_key(cert.toBeSigned.verifyKeyIndicator.choice.verificationKey);
            break;
        default:
            throw std::runtime_error("unable to fetch public key from certificate");
    }
}

std::string get_name(const Vanetza_Security_Certificate_t& cert)
{
    std::string name;
    if (cert.toBeSigned.id.present == Vanetza_Security_CertificateId_PR_name) {
        const UTF8String_t& hostname = cert.toBeSigned.id.choice.name;
        name = std::string { hostname.buf, hostname.buf + hostname.size };
    }
    return name;
}

} // namespace pki
} // namespace vanetza
