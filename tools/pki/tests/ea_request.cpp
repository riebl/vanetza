#include "ea_request.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "encrypted_data.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "recover_key.hpp"
#include "signed_data.hpp"
#include "stub_certificate.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerEcRequest.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <gtest/gtest.h>
#include <memory>

namespace vanetza
{
namespace pki
{

// Fixture that provides a SecurityModule with in-memory credential storage and
// a fresh bootstrap/verification key pair.
class EnrolmentRequestTest : public ::testing::Test
{
protected:
    EnrolmentRequestTest() : m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials)
    {
    }

    EnrolmentRequestParameters make_params(KeyType type = KeyType::NistP256)
    {
        EnrolmentRequestParameters params;
        params.its_id = "test-station-42";
        create_verification_key(params, type);
        params.outer_signer_key = m_security.create_signing_key(type).value();
        return params;
    }

    // key to be certified: public key for the request, its private key signs the POP
    void create_verification_key(EnrolmentRequestParameters& params, KeyType type)
    {
        params.pop_signer_key = m_security.create_signing_key(type).value();
        params.verification_key = m_security.public_key(params.pop_signer_key).value();
    }

    // Decode the unsecuredData payload of a signed Ieee1609Dot2Data into the given wrapper type.
    template<class Wrapper> static Wrapper decode_unsecured(const Vanetza_Security_SignedData_t& signed_data)
    {
        const auto& payload = signed_data.tbsData->payload->data->content->choice.unsecuredData;
        Wrapper w;
        EXPECT_TRUE(w.decode(payload.buf, payload.size));
        return w;
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
    OpenSslCryptoProvider m_crypto;
};

// The builder must reject parameters that do not satisfy ETSI TS 102 941 / IEEE 1609.2 basic invariants.
TEST_F(EnrolmentRequestTest, rejects_empty_its_id)
{
    auto params = make_params();
    params.its_id.clear();
    EXPECT_THROW(build_signed_enrolment_request(m_security, m_crypto, params), std::invalid_argument);
}

// The signed output must parse as an EtsiTs103097Data-Signed with the exact
// structure specified in ETSI TS 102 941 clause 6.2.3.2:
//   Ieee1609Dot2Data(signedData(tbsData.payload.data = unsecured(<EtsiTs102941Data>), signer = self))
TEST_F(EnrolmentRequestTest, outer_structure_matches_TS102941)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    EXPECT_EQ(3u, outer->protocolVersion);
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_signedData, outer->content->present);
    const auto* sd = outer->content->choice.signedData;
    ASSERT_NE(nullptr, sd);
    EXPECT_EQ(Vanetza_Security_HashAlgorithm_sha256, sd->hashId);
    EXPECT_EQ(Vanetza_Security_SignerIdentifier_PR_self, sd->signer.present);
    ASSERT_NE(nullptr, sd->tbsData);
    EXPECT_EQ(aid::SCR, sd->tbsData->headerInfo.psid);
    ASSERT_NE(nullptr, sd->tbsData->payload);
    ASSERT_NE(nullptr, sd->tbsData->payload->data);
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData, sd->tbsData->payload->data->content->present);
}

// The outer signature must verify against the canonical (bootstrap) key, as
// required by ETSI TS 103 525-2 clause 5.2.2.1 (SECPKI_ITSS_ENR_02_BV).
TEST_F(EnrolmentRequestTest, outer_signature_verifies_with_canonical_key)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    const auto& sd = *outer->content->choice.signedData;

    Sha256Hash digest = calculate_digest<Sha256Hash>(m_crypto, *sd.tbsData, nullptr);
    Signature signature = make_signature(sd.signature);
    EXPECT_TRUE(m_crypto.verify(digest, signature, m_security.public_key(params.outer_signer_key).value()).value());
}

// The POP signature carried in the EtsiTs102941Data enrolmentRequest content
// must verify against the *new* verification key (IEEE 1609.2 / TS 102 941
// proof-of-possession).
TEST_F(EnrolmentRequestTest, pop_signature_verifies_with_verification_key)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    MgmtData mgmt = decode_unsecured<MgmtData>(*outer->content->choice.signedData);
    ASSERT_EQ(Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest, mgmt->content.present);

    const auto& pop = mgmt->content.choice.enrolmentRequest;
    EXPECT_EQ(3u, pop.protocolVersion);
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_signedData, pop.content->present);
    const auto& pop_sd = *pop.content->choice.signedData;
    EXPECT_EQ(Vanetza_Security_SignerIdentifier_PR_self, pop_sd.signer.present);

    Sha256Hash digest = calculate_digest<Sha256Hash>(m_crypto, *pop_sd.tbsData, nullptr);
    Signature signature = make_signature(pop_sd.signature);
    EXPECT_TRUE(m_crypto.verify(digest, signature, params.verification_key).value());
}

// The innermost InnerEcRequest must carry the inputs unchanged: itsId, the
// requested verification key, and the permission list.
TEST_F(EnrolmentRequestTest, inner_ec_request_carries_inputs)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    MgmtData mgmt = decode_unsecured<MgmtData>(*outer->content->choice.signedData);

    // Extract inner request from the POP's unsecured payload
    const auto& pop_sd = *mgmt->content.choice.enrolmentRequest.content->choice.signedData;
    asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest_t> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    const auto& pop_payload = pop_sd.tbsData->payload->data->content->choice.unsecuredData;
    ASSERT_TRUE(inner.decode(pop_payload.buf, pop_payload.size));

    EXPECT_EQ(params.its_id.size(), static_cast<size_t>(inner->itsId.size));
    EXPECT_EQ(0, std::memcmp(inner->itsId.buf, params.its_id.data(), inner->itsId.size));
    EXPECT_EQ(Vanetza_Security_CertificateFormat_ts103097v131, inner->certificateFormat);

    ASSERT_NE(nullptr, inner->requestedSubjectAttributes.appPermissions);
    ASSERT_EQ(1, inner->requestedSubjectAttributes.appPermissions->list.count);
    auto* first = inner->requestedSubjectAttributes.appPermissions->list.array[0];
    EXPECT_EQ(static_cast<long>(aid::SCR), first->psid);
    EXPECT_NE(nullptr, first->ssp);
}

// The verification key placed inside the InnerEcRequest must match the
// curve/encoding expected for its KeyType.
TEST_F(EnrolmentRequestTest, inner_verification_key_matches_curve)
{
    for (auto key_type : { KeyType::NistP256, KeyType::BrainpoolP256r1, KeyType::BrainpoolP384r1 }) {
        auto params = make_params(key_type);
        ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

        SignedData outer;
        ASSERT_TRUE(outer.decode(encoded));
        MgmtData mgmt = decode_unsecured<MgmtData>(*outer->content->choice.signedData);
        const auto& pop_sd = *mgmt->content.choice.enrolmentRequest.content->choice.signedData;
        asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest_t> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
        const auto& pop_payload = pop_sd.tbsData->payload->data->content->choice.unsecuredData;
        ASSERT_TRUE(inner.decode(pop_payload.buf, pop_payload.size));

        const auto& vkey = inner->publicKeys.verificationKey;
        switch (key_type) {
            case KeyType::NistP256:
                EXPECT_EQ(Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256, vkey.present);
                break;
            case KeyType::BrainpoolP256r1:
                EXPECT_EQ(Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP256r1, vkey.present);
                break;
            case KeyType::BrainpoolP384r1:
                EXPECT_EQ(Vanetza_Security_PublicVerificationKey_PR_ecdsaBrainpoolP384r1, vkey.present);
                break;
            default:
                FAIL() << "unexpected key type";
        }
    }
}

// ETSI TS 103 097 v1.3.1 clause 7.2.2 "Enrolment credential":
//   The appPermissions of an enrolment credential shall contain only the PSID
//   for secured certificate requests (SCR, 623).
// This is also what the TS 103 525-3 abstract test suite requests in its
// reference inner EC request, and what the 0_EU-EA_L0 EA's certIssuePermissions
// authorise it to issue. Requesting CA/DENM/etc. permissions on the EC causes
// the EA to reject the request (often with an opaque error).
//
// The builder is permissive by design: It accepts whatever the caller passes
// so that test tools can also exercise non-conformant requests. But we fix
// the *conformant* expected shape in a regression test so drift is caught.
TEST_F(EnrolmentRequestTest, conformant_EC_permission_is_SCR_only_TS103097_7_2_2)
{
    EnrolmentRequestParameters params;
    params.its_id = "station-conformant";
    create_verification_key(params, KeyType::NistP256);
    params.outer_signer_key = m_security.create_signing_key(KeyType::NistP256).value();
    // TS 103 525-3 reference value PX_INNER_EC_CERTFICATE_BITMAP_SSP_SCR

    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);
    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    MgmtData mgmt = decode_unsecured<MgmtData>(*outer->content->choice.signedData);
    const auto& pop_sd = *mgmt->content.choice.enrolmentRequest.content->choice.signedData;
    asn1::asn1c_oer_wrapper<Vanetza_Security_InnerEcRequest_t> inner(asn_DEF_Vanetza_Security_InnerEcRequest);
    const auto& pop_payload = pop_sd.tbsData->payload->data->content->choice.unsecuredData;
    ASSERT_TRUE(inner.decode(pop_payload.buf, pop_payload.size));

    const auto* perms = inner->requestedSubjectAttributes.appPermissions;
    ASSERT_NE(nullptr, perms);
    ASSERT_EQ(1, perms->list.count);
    EXPECT_EQ(static_cast<long>(aid::SCR), perms->list.array[0]->psid);
    ASSERT_NE(nullptr, perms->list.array[0]->ssp);
    EXPECT_EQ(Vanetza_Security_ServiceSpecificPermissions_PR_bitmapSsp, perms->list.array[0]->ssp->present);
}

// Mixed-curve stress: use Brainpool for the bootstrap key and NIST for the
// verification key (or vice versa) and verify both signatures still validate.
// This catches bugs where the code assumes both keys share a curve.
TEST_F(EnrolmentRequestTest, mixed_curves_still_verify)
{
    EnrolmentRequestParameters params;
    params.its_id = "mixed-curve-station";
    create_verification_key(params, KeyType::BrainpoolP256r1);
    params.outer_signer_key = m_security.create_signing_key(KeyType::NistP256).value();

    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);
    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    const auto& outer_sd = *outer->content->choice.signedData;
    const Sha256Hash outer_digest = calculate_digest<Sha256Hash>(m_crypto, *outer_sd.tbsData, nullptr);
    const PublicKey outer_signer = m_security.public_key(params.outer_signer_key).value();
    EXPECT_TRUE(m_crypto.verify(outer_digest, make_signature(outer_sd.signature), outer_signer).value());

    MgmtData mgmt = decode_unsecured<MgmtData>(outer_sd);
    const auto& pop_sd = *mgmt->content.choice.enrolmentRequest.content->choice.signedData;
    const Sha256Hash pop_digest = calculate_digest<Sha256Hash>(m_crypto, *pop_sd.tbsData, nullptr);
    EXPECT_TRUE(m_crypto.verify(pop_digest, make_signature(pop_sd.signature), params.verification_key).value());
}

// TS 102 941 §6.2.3.2.1: for a re-keying (renewal) enrolment request, the
// outer EtsiTs103097Data-Signed shall use SignerIdentifier = digest holding
// HashedId8 of the current EC, and the signature shall be computed with the
// EC's private key. Passing `outer_signer_certificate` selects this variant.
TEST_F(EnrolmentRequestTest, outer_digest_signed_when_certificate_provided)
{
    // Stand-in EC: a verification-key-only stub certificate whose private key
    // the security module can sign with.
    KeyReference ec_key = m_security.create_signing_key(KeyType::NistP256).value();
    Certificate ec_cert = build_stub_certificate(m_security.public_key(ec_key).value());

    EnrolmentRequestParameters params;
    params.its_id = "renewal-station"; // would be HashedId8 bytes in real use
    create_verification_key(params, KeyType::NistP256);
    params.outer_signer_key = ec_key;
    params.outer_signer_certificate = &ec_cert;

    ByteBuffer encoded = build_signed_enrolment_request(m_security, m_crypto, params);

    SignedData outer;
    ASSERT_TRUE(outer.decode(encoded));
    const auto& sd = *outer->content->choice.signedData;

    // signer.present == digest, and digest matches HashedId8(ec_cert)
    ASSERT_EQ(Vanetza_Security_SignerIdentifier_PR_digest, sd.signer.present);
    HashedId8 expected_hid8 = ec_cert.calculate_hashed_id8(m_crypto);
    EXPECT_TRUE(sd.signer.choice.digest == expected_hid8.octets);

    // signature verifies over calculate_digest(tbs, &ec_cert) using the EC key
    Sha256Hash digest = calculate_digest<Sha256Hash>(m_crypto, *sd.tbsData, &ec_cert.raw());
    EXPECT_TRUE(m_crypto.verify(digest, make_signature(sd.signature), m_security.public_key(ec_key).value()).value());

    // PoP (inner) remains signer = self regardless of outer signer choice.
    MgmtData mgmt = decode_unsecured<MgmtData>(sd);
    const auto& pop_sd = *mgmt->content.choice.enrolmentRequest.content->choice.signedData;
    EXPECT_EQ(Vanetza_Security_SignerIdentifier_PR_self, pop_sd.signer.present);
}

// The EA recovers the request's key to encrypt its response with (TS 102 941 §6.2.3.2.2).
TEST_F(EnrolmentRequestTest, request_key_is_encrypted_for_ea)
{
    // brainpoolP256r1 complements the NIST P-256 encryption keys of the AT request tests
    const PrivateKey ea_encryption_key = generate_private_key(KeyType::BrainpoolP256r1);
    const PublicKey ea_encryption_public_key = derive_public_key(ea_encryption_key);
    const Certificate ea =
        build_stub_certificate(derive_public_key(generate_private_key(KeyType::NistP256)), &ea_encryption_public_key);
    EncryptedRequest request = build_enrolment_request(m_security, m_crypto, make_params(), ea);

    EXPECT_EQ(request.key, recover_key(m_crypto, *request.message, ea_encryption_key, ea));
}

} // namespace pki
} // namespace vanetza
