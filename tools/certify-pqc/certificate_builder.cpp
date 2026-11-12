#include "certificate_builder.hpp"
#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(Certificate.h)
#include VANETZA_ASN1_SECURITY_HEADER(PsidGroupPermissions.h)
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/pqc/hybrid_certificate.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace vanetza
{
namespace security
{
namespace pqc
{
namespace certificate_builder
{

namespace
{

void assign_octets(OCTET_STRING_t& destination, const void* source, std::size_t size)
{
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
            OCTET_STRING_fromBuf(
                &destination, static_cast<const char*>(source), static_cast<int>(size)) != 0) {
        throw std::runtime_error("cannot allocate ASN.1 octet string");
    }
}

::vanetza::security::PublicKey query_public_key(SecurityModule& module, const KeyReference& key)
{
    auto public_key = module.public_key(key);
    if (!public_key) {
        throw std::runtime_error("cannot query public key of ECC key reference: " + public_key.error().message());
    }
    return std::move(*public_key);
}

void set_verification_key(v3::Certificate& certificate, const ::vanetza::security::PublicKey& public_key)
{
    auto& indicator = certificate->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    auto& verification_key = indicator.choice.verificationKey;
    verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    verification_key.choice.ecdsaNistP256 =
        v3::to_asn1(compress_public_key(public_key));
}

void set_encryption_key(v3::Certificate& certificate, const ::vanetza::security::PublicKey& public_key)
{
    certificate->toBeSigned.encryptionKey =
        vanetza::asn1::allocate<v3::asn1::PublicEncryptionKey>();
    auto& encryption_key = certificate->toBeSigned.encryptionKey->publicKey;
    encryption_key.present = Vanetza_Security_BasePublicEncryptionKey_PR_eciesNistP256;
    encryption_key.choice.eciesNistP256 =
        v3::to_asn1(compress_public_key(public_key));
}

void set_issuer(CryptoProvider& crypto, v3::Certificate& certificate, const v3::Certificate* issuer)
{
    if (!issuer) {
        certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        certificate->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
        return;
    }

    const auto digest = issuer->calculate_digest(crypto);
    if (!digest) {
        throw std::invalid_argument("issuer certificate has no canonical digest");
    }
    certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    assign_octets(
        certificate->issuer.choice.sha256AndDigest,
        digest->data(), digest->size());
}

void set_subject_name(v3::Certificate& certificate, const std::string& name)
{
    if (name.empty()) {
        throw std::invalid_argument("CA subject name must not be empty");
    }
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
    assign_octets(certificate->toBeSigned.id.choice.name, name.data(), name.size());
}

void set_validity(
    v3::Certificate& certificate, Clock::time_point now, int validity_days)
{
    constexpr int maximum_days = std::numeric_limits<unsigned short>::max() / 24;
    if (validity_days < 1 || validity_days > maximum_days) {
        throw std::invalid_argument("validity must be between 1 and 2730 days");
    }

    certificate->toBeSigned.validityPeriod.start =
        v2::convert_time32(now - std::chrono::hours(1));
    certificate->toBeSigned.validityPeriod.duration.present =
        Vanetza_Security_Duration_PR_hours;
    certificate->toBeSigned.validityPeriod.duration.choice.hours = validity_days * 24;
}

void initialize_certificate(
    CryptoProvider& crypto, v3::Certificate& certificate, const ::vanetza::security::PublicKey& subject_key,
    const v3::Certificate* issuer, int validity_days, Clock::time_point now)
{
    certificate->version = 3;
    certificate->type = Vanetza_Security_CertificateType_explicit;
    set_issuer(crypto, certificate, issuer);

    static const std::array<char, 3> craca_id {{ 0, 0, 0 }};
    assign_octets(certificate->toBeSigned.cracaId, craca_id.data(), craca_id.size());
    certificate->toBeSigned.crlSeries = 0;
    set_validity(certificate, now, validity_days);
    set_verification_key(certificate, subject_key);
}

std::vector<ItsAid> effective_issue_aids(const std::vector<ItsAid>& aids)
{
    if (!aids.empty()) {
        return aids;
    }
    return { aid::CA, aid::DEN, aid::CP, aid::GN_MGMT, aid::IPV6_ROUTING };
}

std::vector<ItsAid> effective_application_aids(const std::vector<ItsAid>& aids)
{
    return aids.empty() ? std::vector<ItsAid> { aid::CA, aid::DEN } : aids;
}

void add_issue_permission_for_aid(
    v3::asn1::PsidGroupPermissions* group, ItsAid application_id)
{
    switch (application_id) {
        case aid::CA:
            v3::add_psid_group_permission(
                group, application_id, { 0x01, 0xff, 0xfc }, { 0xff, 0x00, 0x03 });
            break;
        case aid::DEN:
            v3::add_psid_group_permission(
                group, application_id,
                { 0x01, 0xff, 0xff, 0xff }, { 0xff, 0x00, 0x00, 0x00 });
            break;
        case aid::CP:
            v3::add_psid_group_permission(group, application_id, { 0x00 }, { 0xff });
            break;
        case aid::TLM:
            v3::add_psid_group_permission(group, application_id, { 0x01, 0xe0 }, { 0xff, 0x1f });
            break;
        case aid::RLT:
            v3::add_psid_group_permission(group, application_id, { 0x01, 0xc0 }, { 0xff, 0x3f });
            break;
        case aid::IVI:
            v3::add_psid_group_permission(
                group, application_id,
                { 0x01, 0xff, 0xff, 0xff, 0xff, 0xf8 },
                { 0xff, 0x00, 0x00, 0x00, 0x00, 0x07 });
            break;
        case aid::TLC_R:
            v3::add_psid_group_permission(
                group, application_id,
                { 0x02, 0xff, 0xff, 0xe0 }, { 0xff, 0x00, 0x00, 0x1f });
            break;
        case aid::GN_MGMT:
        case aid::IPV6_ROUTING:
        default:
            v3::add_psid_group_permission(group, application_id, { 0x00 }, { 0xff });
            break;
    }
}

void add_issue_permissions(v3::Certificate& certificate, const std::vector<ItsAid>& aids)
{
    auto* group = vanetza::asn1::allocate<v3::asn1::PsidGroupPermissions>();
    group->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    for (ItsAid application_id : effective_issue_aids(aids)) {
        add_issue_permission_for_aid(group, application_id);
    }
    certificate.add_cert_issue_permission(group);
}

void add_application_permissions(v3::Certificate& certificate, const std::vector<ItsAid>& aids)
{
    for (ItsAid application_id : effective_application_aids(aids)) {
        if (application_id == aid::CA) {
            certificate.add_app_permission(application_id, ByteBuffer { 1, 0, 0 });
        } else if (application_id == aid::DEN) {
            certificate.add_app_permission(application_id, ByteBuffer { 1, 0, 0, 0 });
        } else {
            certificate.add_app_permission(application_id, {});
        }
    }
}

v3::Certificate canonical_certificate(v3::Certificate certificate)
{
    auto canonical = certificate.canonicalize();
    if (!canonical) {
        throw std::runtime_error("generated certificate cannot be canonicalized");
    }
    std::string error;
    if (!canonical->validate(error)) {
        throw std::runtime_error("generated certificate violates ASN.1 constraints: " + error);
    }
    return std::move(*canonical);
}

} // namespace

v3::Certificate build_ecc_root_certificate(
    CryptoProvider& crypto, SecurityModule& module, const KeyReference& subject_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, query_public_key(module, subject_key), nullptr, parameters.validity_days, now);
    set_subject_name(certificate, parameters.subject_name);
    add_issue_permissions(certificate, parameters.application_ids);
    certificate.add_app_permission(aid::CRL, ByteBuffer { 1 });
    certificate.add_app_permission(aid::CTL, ByteBuffer { 0x18 });

    sign_primary_certificate(certificate, nullptr, crypto, module, subject_key);
    return canonical_certificate(std::move(certificate));
}

v3::Certificate build_hybrid_root_certificate(
    CryptoProvider& crypto, SecurityModule& module, Backend& pqc_backend,
    const KeyReference& subject_key, const SigningKey& subject_pqc_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, query_public_key(module, subject_key), nullptr, parameters.validity_days, now);
    set_subject_name(certificate, parameters.subject_name);
    add_issue_permissions(certificate, parameters.application_ids);
    certificate.add_app_permission(aid::CRL, ByteBuffer { 1 });
    certificate.add_app_permission(aid::CTL, ByteBuffer { 0x18 });

    set_alternative_public_key(certificate, subject_pqc_key.public_key);
    sign_alternative_certificate(certificate, nullptr, crypto, pqc_backend, subject_pqc_key.reference);
    sign_primary_certificate(certificate, nullptr, crypto, module, subject_key);
    return canonical_certificate(std::move(certificate));
}

v3::Certificate build_ecc_authorization_authority_certificate(
    CryptoProvider& crypto, SecurityModule& module, const KeyReference& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, subject_key, &issuer_certificate, parameters.validity_days, now);
    set_subject_name(certificate, parameters.subject_name);
    add_issue_permissions(certificate, parameters.application_ids);
    set_encryption_key(certificate, subject_key);

    sign_primary_certificate(certificate, &issuer_certificate, crypto, module, issuer_key);
    return canonical_certificate(std::move(certificate));
}

v3::Certificate build_hybrid_authorization_authority_certificate(
    CryptoProvider& crypto, SecurityModule& module, Backend& pqc_backend,
    const KeyReference& issuer_key, const KeyReference& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key, const PublicKey& subject_pqc_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, subject_key, &issuer_certificate, parameters.validity_days, now);
    set_subject_name(certificate, parameters.subject_name);
    add_issue_permissions(certificate, parameters.application_ids);
    set_encryption_key(certificate, subject_key);

    set_alternative_public_key(certificate, subject_pqc_key);
    sign_alternative_certificate(certificate, &issuer_certificate, crypto, pqc_backend, issuer_pqc_key);
    sign_primary_certificate(certificate, &issuer_certificate, crypto, module, issuer_key);
    return canonical_certificate(std::move(certificate));
}

v3::Certificate build_ecc_authorization_ticket(
    CryptoProvider& crypto, SecurityModule& module, const KeyReference& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, subject_key, &issuer_certificate, parameters.validity_days, now);
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    add_application_permissions(certificate, parameters.application_ids);

    sign_primary_certificate(certificate, &issuer_certificate, crypto, module, issuer_key);
    return canonical_certificate(std::move(certificate));
}

v3::Certificate build_hybrid_authorization_ticket(
    CryptoProvider& crypto, SecurityModule& module, Backend& pqc_backend,
    const KeyReference& issuer_key, const KeyReference& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters& parameters, Clock::time_point now)
{
    v3::Certificate certificate;
    initialize_certificate(
        crypto, certificate, subject_key, &issuer_certificate, parameters.validity_days, now);
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    add_application_permissions(certificate, parameters.application_ids);

    sign_alternative_certificate(certificate, &issuer_certificate, crypto, pqc_backend, issuer_pqc_key);
    sign_primary_certificate(certificate, &issuer_certificate, crypto, module, issuer_key);
    return canonical_certificate(std::move(certificate));
}

} // namespace certificate_builder
} // namespace pqc
} // namespace security
} // namespace vanetza
