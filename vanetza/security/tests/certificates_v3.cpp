#include <vanetza/security/tests/certificates_v3.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <array>
#include <cstdint>
#include <stdexcept>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

void assign_compressed(asn1::EccP256CurvePoint& point, const PublicKey& key)
{
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
            throw std::invalid_argument("public key of certificate is not compressed");
    }
}

void assign_compressed(asn1::EccP384CurvePoint& point, const PublicKey& key)
{
    switch (key.compression) {
        case KeyCompression::Y0:
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_0;
            vanetza::asn1::assign(point.choice.compressed_y_0, key.x);
            break;
        case KeyCompression::Y1:
            point.present = Vanetza_Security_EccP384CurvePoint_PR_compressed_y_1;
            vanetza::asn1::assign(point.choice.compressed_y_1, key.x);
            break;
        default:
            throw std::invalid_argument("public key of certificate is not compressed");
    }
}

void assign_verification_key(asn1::PublicVerificationKey& verification_key, const PublicKey& key)
{
    switch (key.type) {
        case KeyType::NistP256:
            verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
            assign_compressed(verification_key.choice.ecdsaNistP256, key);
            break;
        case KeyType::BrainpoolP256r1:
            verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1;
            assign_compressed(verification_key.choice.ecdsaBrainpoolP256r1, key);
            break;
        case KeyType::BrainpoolP384r1:
            verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1;
            assign_compressed(verification_key.choice.ecdsaBrainpoolP384r1, key);
            break;
        default:
            throw std::invalid_argument("unsupported key type of certificate");
    }
}

// explicit certificate of a compressed public key, issued by a fictitious certificate and yet unsigned
Certificate make_certificate(const PublicKey& key, Clock::time_point start)
{
    Certificate certificate;
    certificate->version = 3;
    certificate->type = Vanetza_Security_CertificateType_explicit;
    certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    const std::array<std::uint8_t, 8> issuer_digest = { 1, 2, 3, 4, 5, 6, 7, 8 };
    vanetza::asn1::assign(certificate->issuer.choice.sha256AndDigest, issuer_digest);
    certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    const std::array<std::uint8_t, 3> craca_id = { 0, 0, 0 };
    vanetza::asn1::assign(certificate->toBeSigned.cracaId, craca_id);
    certificate->toBeSigned.crlSeries = 0;
    certificate->toBeSigned.validityPeriod.start = convert_time32(start);
    certificate->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
    certificate->toBeSigned.validityPeriod.duration.choice.hours = 168;

    auto& indicator = certificate->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    assign_verification_key(indicator.choice.verificationKey, key);
    return certificate;
}

} // namespace

Certificate make_authorization_ticket(const PublicKey& key, Clock::time_point start)
{
    Certificate ticket = make_certificate(key, start);
    ticket.add_app_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff }));
    return ticket;
}

Certificate make_authorization_authority(const PublicKey& key, Clock::time_point start)
{
    Certificate authority = make_certificate(key, start);
    auto permissions = vanetza::asn1::allocate<asn1::PsidGroupPermissions>();
    permissions->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_all;
    authority.add_cert_issue_permission(permissions);
    return authority;
}

} // namespace v3
} // namespace security
} // namespace vanetza
