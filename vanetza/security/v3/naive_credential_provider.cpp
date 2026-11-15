#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/naive_credential_provider.hpp>
#include <array>
#include <chrono>
#include <string>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

// all keys of the naive chain are NIST P-256 keys, signed by SHA-256 hashes
constexpr KeyType key_type = KeyType::NistP256;
constexpr HashAlgorithm hash_algorithm = HashAlgorithm::SHA256;

// explicit certificate of a public key with a validity period, yet without issuer and signature
Certificate make_certificate(const PublicKey& key, Clock::time_point start, Vanetza_Security_Duration_PR unit,
    std::uint16_t duration)
{
    Certificate certificate;
    certificate->version = 3;
    certificate->type = Vanetza_Security_CertificateType_explicit;
    const std::array<std::uint8_t, 3> craca_id = { 0, 0, 0 };
    vanetza::asn1::assign(certificate->toBeSigned.cracaId, craca_id);
    certificate->toBeSigned.crlSeries = 0;
    certificate->toBeSigned.validityPeriod.start = convert_time32(start);
    certificate->toBeSigned.validityPeriod.duration.present = unit;
    if (unit == Vanetza_Security_Duration_PR_years) {
        certificate->toBeSigned.validityPeriod.duration.choice.years = duration;
    } else {
        certificate->toBeSigned.validityPeriod.duration.choice.hours = duration;
    }

    auto& indicator = certificate->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    indicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    auto& point = indicator.choice.verificationKey.choice.ecdsaNistP256;
    switch (key.compression) {
        case KeyCompression::Y0:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
            vanetza::asn1::assign(point.choice.compressed_y_0, key.x);
            break;
        case KeyCompression::Y1:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
            vanetza::asn1::assign(point.choice.compressed_y_1, key.x);
            break;
        default:
            point.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
            vanetza::asn1::assign(point.choice.uncompressedP256.x, key.x);
            vanetza::asn1::assign(point.choice.uncompressedP256.y, key.y);
            break;
    }
    return certificate;
}

void set_name(Certificate& certificate, const std::string& name)
{
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    OCTET_STRING_fromBuf(&certificate->toBeSigned.id.choice.name, name.data(), name.size());
}

// issuer is named by its certificate digest
std::error_code set_issuer(Certificate& certificate, const Certificate& issuer, CryptoProvider& crypto)
{
    const boost::optional<HashedId8> digest = issuer.calculate_digest(crypto);
    if (!digest) {
        // issuer certificate failing its canonical encoding
        return std::make_error_code(std::errc::invalid_argument);
    }
    certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    vanetza::asn1::assign(certificate->issuer.choice.sha256AndDigest, *digest);
    return {};
}

// permissions to issue certificates for messages, see C-ITS Point of Contact protocol v3.0, annex I.3.8
void add_message_issue_permissions(Certificate& certificate)
{
    asn1::PsidGroupPermissions* permissions = vanetza::asn1::allocate<asn1::PsidGroupPermissions>();
    permissions->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    add_psid_group_permission(permissions, aid::CA, { 0x01, 0xff, 0xfc }, { 0xff, 0x00, 0x03 });
    add_psid_group_permission(permissions, aid::DEN, { 0x01, 0xff, 0xff, 0xff }, { 0xff, 0x00, 0x00, 0x00 });
    add_psid_group_permission(permissions, aid::TLM, { 0x01, 0xe0 }, { 0xff, 0x1f });
    add_psid_group_permission(permissions, aid::RLT, { 0x01, 0xc0 }, { 0xff, 0x3f });
    add_psid_group_permission(permissions, aid::IVI,
        { 0x01, 0xff, 0xff, 0xff, 0xff, 0xf8 }, { 0xff, 0x00, 0x00, 0x00, 0x00, 0x07 });
    add_psid_group_permission(permissions, aid::TLC_R, { 0x02, 0xff, 0xff, 0xe0 }, { 0xff, 0x00, 0x00, 0x1f });
    add_psid_group_permission(permissions, aid::GN_MGMT, { 0x00 }, { 0xff });
    certificate.add_cert_issue_permission(permissions);
}

// IEEE 1609.2 clause 5.3.1.2.2: self-signed certificates hash an empty signer input
ByteBuffer calculate_self_signed_hash(CryptoProvider& crypto, const Certificate& certificate)
{
    const boost::optional<Certificate> canonical = certificate.canonicalize();
    if (!canonical) {
        return ByteBuffer {};
    }
    vanetza::asn1::asn1c_error error;
    const ByteBuffer tbs = vanetza::asn1::encode_oer(
        asn_DEF_Vanetza_Security_ToBeSignedCertificate, &canonical->content()->toBeSigned, error);
    if (error) {
        return ByteBuffer {};
    }

    ByteBuffer concatenated = calculate_hash(crypto, hash_algorithm, tbs);
    const ByteBuffer signer = calculate_hash(crypto, hash_algorithm, ByteBuffer {});
    concatenated.insert(concatenated.end(), signer.begin(), signer.end());
    return calculate_hash(crypto, hash_algorithm, concatenated);
}

/**
 * Sign certificate by IEEE 1609.2 clause 5.3.1.2.2
 * \param issuer certificate of signer, nullptr for a self-signed certificate
 * \param key signer's key
 */
std::error_code sign(Certificate& certificate, const Certificate* issuer, const KeyReference& key,
    SecurityModule& module, CryptoProvider& crypto)
{
    const ByteBuffer hash = issuer ?
        calculate_certificate_hash(crypto, hash_algorithm, certificate, *issuer) :
        calculate_self_signed_hash(crypto, certificate);
    if (hash.empty()) {
        // certificate failing its canonical encoding
        return std::make_error_code(std::errc::invalid_argument);
    }

    const expected<Signature> signature = module.sign(hash, key);
    if (!signature) {
        return signature.error();
    }
    EcdsaSignature ecdsa;
    ecdsa.R = X_Coordinate_Only { signature->r };
    ecdsa.s = signature->s;
    certificate.set_signature(ecdsa);
    return {};
}

} // namespace

NaiveCredentialProvider::NaiveCredentialProvider(SecurityModule& module, CryptoProvider& crypto) :
    m_module(module), m_crypto(crypto)
{
}

NaiveCredentialProvider::~NaiveCredentialProvider()
{
    discard_keys();
}

std::error_code NaiveCredentialProvider::issue_certificates(Clock::time_point now)
{
    if (!m_credential.key.data.empty()) {
        return issue_ticket(now);
    }

    const std::error_code error = create_chain(now);
    if (error) {
        // a partly created chain is discarded, i.e. the next call starts over
        discard_keys();
    }
    return error;
}

std::error_code NaiveCredentialProvider::create_chain(Clock::time_point now)
{
    // creates a key of the chain and its public key
    auto create_key = [this](KeyReference& reference) -> expected<PublicKey> {
        expected<KeyReference> key = m_module.create_signing_key(key_type);
        if (!key) {
            return key.error();
        }
        reference = std::move(*key);
        return m_module.public_key(reference);
    };

    const Clock::time_point start = now - std::chrono::hours(1);
    std::error_code error;

    const expected<PublicKey> root_key = create_key(m_root_key);
    if (!root_key) {
        return root_key.error();
    }
    m_root_certificate = make_certificate(*root_key, start, Vanetza_Security_Duration_PR_years, 4);
    m_root_certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
    set_name(m_root_certificate, "Naive Root CA");
    m_root_certificate.add_app_permission(aid::CRL, ByteBuffer({ 0x01 }));
    m_root_certificate.add_app_permission(aid::CTL, ByteBuffer({ 0x18 }));
    asn1::PsidGroupPermissions* scr_permission = vanetza::asn1::allocate<asn1::PsidGroupPermissions>();
    scr_permission->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    add_psid_group_permission(scr_permission, aid::SCR, { 0x01, 0x3e }, { 0xff, 0xc1 });
    m_root_certificate.add_cert_issue_permission(scr_permission);
    add_message_issue_permissions(m_root_certificate);
    error = sign(m_root_certificate, nullptr, m_root_key, m_module, m_crypto);
    if (error) {
        return error;
    }

    const expected<PublicKey> aa_key = create_key(m_aa_key);
    if (!aa_key) {
        return aa_key.error();
    }
    m_aa_certificate = make_certificate(*aa_key, start, Vanetza_Security_Duration_PR_years, 4);
    set_name(m_aa_certificate, "Naive Authorization CA");
    add_message_issue_permissions(m_aa_certificate);
    error = set_issuer(m_aa_certificate, m_root_certificate, m_crypto);
    if (error) {
        return error;
    }
    error = sign(m_aa_certificate, &m_root_certificate, m_root_key, m_module, m_crypto);
    if (error) {
        return error;
    }

    const expected<PublicKey> ticket_key = create_key(m_credential.key);
    if (!ticket_key) {
        return ticket_key.error();
    }
    return issue_ticket(now);
}

std::error_code NaiveCredentialProvider::issue_ticket(Clock::time_point now)
{
    const expected<PublicKey> key = m_module.public_key(m_credential.key);
    if (!key) {
        return key.error();
    }

    Certificate ticket = make_certificate(*key, now - std::chrono::hours(1), Vanetza_Security_Duration_PR_hours, 23);
    ticket->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    ticket.add_app_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    ticket.add_app_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff }));
    ticket.add_app_permission(aid::GN_MGMT, ByteBuffer({})); // required for beacons
    ticket.add_app_permission(aid::IPV6_ROUTING, ByteBuffer({})); // required for routing tests
    std::error_code error = set_issuer(ticket, m_aa_certificate, m_crypto);
    if (error) {
        return error;
    }
    error = sign(ticket, &m_aa_certificate, m_aa_key, m_module, m_crypto);
    if (!error) {
        m_credential.certificate = std::move(ticket);
    }
    return error;
}

void NaiveCredentialProvider::discard_keys()
{
    for (KeyReference* key : { &m_root_key, &m_aa_key, &m_credential.key }) {
        if (!key->data.empty()) {
            m_module.discard_key(*key);
            key->data.clear();
        }
    }
}

const Credential* NaiveCredentialProvider::signing_credential(ItsAid aid)
{
    return issued() && m_credential.certificate.valid_for_application(aid) ? &m_credential : nullptr;
}

const Certificate* NaiveCredentialProvider::aa_certificate() const
{
    return issued() ? &m_aa_certificate : nullptr;
}

const Certificate* NaiveCredentialProvider::root_certificate() const
{
    return issued() ? &m_root_certificate : nullptr;
}

// keys exist only along with a complete chain, a partly created chain is discarded at once
bool NaiveCredentialProvider::issued() const
{
    return !m_credential.key.data.empty();
}

} // namespace v3
} // namespace security
} // namespace vanetza
