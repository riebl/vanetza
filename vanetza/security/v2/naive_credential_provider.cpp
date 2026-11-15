#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/naive_credential_provider.hpp>
#include <chrono>
#include <string>

namespace vanetza
{
namespace security
{
namespace v2
{

namespace
{

// all keys of the naive chain are NIST P-256 keys
constexpr KeyType key_type = KeyType::NistP256;

// certificate of a subject with verification key and validity period, yet without signer and signature
Certificate make_certificate(SubjectType type, const std::string& name, const security::PublicKey& key,
    Clock::time_point start, Clock::time_point end)
{
    Certificate certificate;

    // section 6.3 and 7.4.2 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = type;
    certificate.subject_info.subject_name.assign(name.begin(), name.end());

    // section 6.6 in TS 103 097 v1.2.1, levels currently undefined
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    // section 7.4.1 in TS 103 097 v1.2.1
    ecdsa_nistp256_with_sha256 ecdsa;
    switch (key.compression) {
        case KeyCompression::Y0:
            ecdsa.public_key = Compressed_Lsb_Y_0 { key.x };
            break;
        case KeyCompression::Y1:
            ecdsa.public_key = Compressed_Lsb_Y_1 { key.x };
            break;
        default:
            ecdsa.public_key = Uncompressed { key.x, key.y };
            break;
    }
    VerificationKey verification_key;
    verification_key.key = ecdsa;
    certificate.subject_attributes.push_back(verification_key);

    // section 6.7 in TS 103 097 v1.2.1
    StartAndEndValidity validity;
    validity.start_validity = convert_time32(start);
    validity.end_validity = convert_time32(end);
    certificate.validity_restriction.push_back(validity);
    return certificate;
}

void add_authority_permissions(Certificate& certificate)
{
    certificate.add_permission(aid::CA);
    certificate.add_permission(aid::DEN);
    certificate.add_permission(aid::GN_MGMT); // required for beacons
    certificate.add_permission(aid::IPV6_ROUTING); // required for routing tests
}

// section 7.4 in TS 103 097 v1.2.1: signature of the SHA-256 digest of the certificate up to its signature
std::error_code sign(Certificate& certificate, const KeyReference& key, SecurityModule& module, CryptoProvider& crypto)
{
    sort(certificate);
    const ByteBuffer data = convert_for_signing(certificate);
    const Sha256Hash digest = crypto.calculate_sha256_hash(data.data(), data.size());
    const expected<security::Signature> signature =
        module.sign(ByteBuffer(digest.octets.begin(), digest.octets.end()), key);
    if (!signature) {
        return signature.error();
    }

    EcdsaSignature ecdsa;
    ecdsa.R = X_Coordinate_Only { signature->r };
    ecdsa.s = signature->s;
    certificate.signature = ecdsa;
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
    auto create_key = [this](KeyReference& reference) -> expected<security::PublicKey> {
        expected<KeyReference> key = m_module.create_signing_key(key_type);
        if (!key) {
            return key.error();
        }
        reference = std::move(*key);
        return m_module.public_key(reference);
    };

    // authorities stay valid beyond renewals of the ticket
    const Clock::time_point start = now - std::chrono::hours(1);
    const Clock::time_point end = now + std::chrono::hours(365 * 24);

    const expected<security::PublicKey> root_key = create_key(m_root_key);
    if (!root_key) {
        return root_key.error();
    }
    m_root_certificate = make_certificate(SubjectType::Root_CA, "Naive Root CA", *root_key, start, end);
    add_authority_permissions(m_root_certificate);
    m_root_certificate.signer_info = nullptr; // self-signed
    std::error_code error = sign(m_root_certificate, m_root_key, m_module, m_crypto);
    if (error) {
        return error;
    }

    const expected<security::PublicKey> aa_key = create_key(m_aa_key);
    if (!aa_key) {
        return aa_key.error();
    }
    Certificate& aa_certificate = m_credential.issuer;
    aa_certificate = make_certificate(SubjectType::Authorization_Authority, "Naive Authorization CA", *aa_key,
        start, end);
    add_authority_permissions(aa_certificate);
    aa_certificate.signer_info = calculate_hash(m_crypto, m_root_certificate);
    error = sign(aa_certificate, m_root_key, m_module, m_crypto);
    if (error) {
        return error;
    }

    const expected<security::PublicKey> ticket_key = create_key(m_credential.key);
    if (!ticket_key) {
        return ticket_key.error();
    }
    return issue_ticket(now);
}

std::error_code NaiveCredentialProvider::issue_ticket(Clock::time_point now)
{
    const expected<security::PublicKey> key = m_module.public_key(m_credential.key);
    if (!key) {
        return key.error();
    }

    // section 7.4.2 in TS 103 097 v1.2.1: subject name of tickets is empty
    Certificate ticket = make_certificate(SubjectType::Authorization_Ticket, std::string {}, *key,
        now - std::chrono::hours(1), now + std::chrono::hours(23));
    ticket.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    ticket.add_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff }));
    ticket.add_permission(aid::GN_MGMT, ByteBuffer({})); // required for beacons
    ticket.add_permission(aid::IPV6_ROUTING, ByteBuffer({})); // required for routing tests
    ticket.signer_info = calculate_hash(m_crypto, m_credential.issuer);

    const std::error_code error = sign(ticket, m_aa_key, m_module, m_crypto);
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

const Credential* NaiveCredentialProvider::signing_credential(ItsAid)
{
    return issued() ? &m_credential : nullptr;
}

const Certificate* NaiveCredentialProvider::aa_certificate() const
{
    return issued() ? &m_credential.issuer : nullptr;
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

} // namespace v2
} // namespace security
} // namespace vanetza
