#include "asn1.hpp"
#include "certificate.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/asn1/security/PsidGroupPermissions.h>
#include <vanetza/asn1/security/PsidSsp.h>
#include <vanetza/asn1/security/SequenceOfPsidGroupPermissions.h>
#include <vanetza/asn1/security/SequenceOfPsidSsp.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdlib>
#include <memory>

namespace vanetza
{
namespace pki
{
namespace
{

PublicKey make_key()
{
    static auto credentials = std::make_shared<MockCredentialStorage>();
    static OpenSslSecurityModule sm(credentials);
    return sm.create_key(KeyType::BrainpoolP256r1);
}

enum class Issuer
{
    Self,
    Digest
};

enum class CertId
{
    Name,
    None
};

void set_issuer(Vanetza_Security_EtsiTs103097Certificate_t& cert, Issuer issuer)
{
    if (issuer == Issuer::Self) {
        cert.issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        cert.issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
    } else {
        static const std::array<char, 8> digest { 1, 2, 3, 4, 5, 6, 7, 8 };
        cert.issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
        OCTET_STRING_fromBuf(&cert.issuer.choice.sha256AndDigest, digest.data(), digest.size());
    }
}

void set_cert_id(Vanetza_Security_ToBeSignedCertificate_t& tbs, CertId id)
{
    if (id == CertId::Name) {
        tbs.id.present = Vanetza_Security_CertificateId_PR_name;
        OCTET_STRING_fromBuf(&tbs.id.choice.name, "test-cert", 9);
    } else {
        tbs.id.present = Vanetza_Security_CertificateId_PR_none;
    }
}

void add_app_perm(Vanetza_Security_ToBeSignedCertificate_t& tbs, ItsAid psid)
{
    if (!tbs.appPermissions) {
        tbs.appPermissions = asn1::allocate<Vanetza_Security_SequenceOfPsidSsp_t>();
    }
    auto* ps = asn1::allocate<Vanetza_Security_PsidSsp_t>();
    ps->psid = static_cast<long>(psid);
    ASN_SEQUENCE_ADD(&tbs.appPermissions->list, ps);
}

void add_cert_issue_perm(Vanetza_Security_ToBeSignedCertificate_t& tbs, ItsAid psid)
{
    if (!tbs.certIssuePermissions) {
        tbs.certIssuePermissions = asn1::allocate<Vanetza_Security_SequenceOfPsidGroupPermissions_t>();
    }
    auto* group = asn1::allocate<Vanetza_Security_PsidGroupPermissions_t>();
    group->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_explicit;
    vanetza::security::v3::add_psid_group_permission(group, psid, { 0x01 }, { 0xff });
    ASN_SEQUENCE_ADD(&tbs.certIssuePermissions->list, group);
}

Certificate build(Issuer issuer, CertId id, const std::vector<ItsAid>& app_perms,
    const std::vector<ItsAid>& cert_issue_perms)
{
    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs103097Certificate_t>
        cert(asn_DEF_Vanetza_Security_EtsiTs103097Certificate);
    cert->version = 3;
    cert->type = Vanetza_Security_CertificateType_explicit;
    set_issuer(*cert, issuer);

    auto& tbs = cert->toBeSigned;
    set_cert_id(tbs, id);
    tbs.cracaId.buf = static_cast<uint8_t*>(std::calloc(3, 1));
    tbs.cracaId.size = 3;
    tbs.crlSeries = 0;
    tbs.validityPeriod.start = 0;
    tbs.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
    tbs.validityPeriod.duration.choice.hours = 24;
    tbs.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    set_verification_key(tbs.verifyKeyIndicator.choice.verificationKey, make_key());

    for (ItsAid p : app_perms) {
        add_app_perm(tbs, p);
    }
    for (ItsAid p : cert_issue_perms) {
        add_cert_issue_perm(tbs, p);
    }

    Certificate result;
    EXPECT_TRUE(result.decode(cert.encode()));
    return result;
}

TEST(CertificateRole, root_ca_self_issued_with_cert_issue_and_crl_ctl_app_perms)
{
    auto cert = build(Issuer::Self, CertId::Name, { aid::CRL, aid::CTL }, { aid::SCR });
    EXPECT_EQ(CertificateRole::RootCa, certificate_role(cert));
}

TEST(CertificateRole, tlm_self_issued_signs_ctl_without_cert_issue)
{
    auto cert = build(Issuer::Self, CertId::Name, { aid::CTL }, {});
    EXPECT_EQ(CertificateRole::Tlm, certificate_role(cert));
}

TEST(CertificateRole, enrolment_authority_issues_scr)
{
    auto cert = build(Issuer::Digest, CertId::Name, { aid::SCR }, { aid::SCR });
    EXPECT_EQ(CertificateRole::EnrolmentAuthority, certificate_role(cert));
}

TEST(CertificateRole, authorization_authority_issues_services)
{
    auto cert = build(Issuer::Digest, CertId::Name, { aid::SCR }, { aid::CA });
    EXPECT_EQ(CertificateRole::AuthorizationAuthority, certificate_role(cert));
}

TEST(CertificateRole, enrolment_credential_has_certificate_id_name)
{
    auto cert = build(Issuer::Digest, CertId::Name, { aid::SCR }, {});
    EXPECT_EQ(CertificateRole::EnrolmentCredential, certificate_role(cert));
}

TEST(CertificateRole, authorization_ticket_has_certificate_id_none)
{
    auto cert = build(Issuer::Digest, CertId::None, { aid::CA }, {});
    EXPECT_EQ(CertificateRole::AuthorizationTicket, certificate_role(cert));
}

TEST(CertificateRole, unknown_when_no_profile_matches)
{
    auto cert = build(Issuer::Self, CertId::Name, { aid::CA }, {});
    EXPECT_EQ(CertificateRole::Unknown, certificate_role(cert));
}

} // namespace
} // namespace pki
} // namespace vanetza
