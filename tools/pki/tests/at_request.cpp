#include "at_request.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "encrypted_data.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "recover_key.hpp"
#include "signed_data.hpp"
#include "stub_certificate.hpp"
#include "validation.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/InnerAtRequest.h>
#include <vanetza/asn1/security/SharedAtRequest.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/hmac.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <gtest/gtest.h>
#include <memory>

namespace vanetza
{
namespace pki
{

class AuthorizationRequestTest : public ::testing::Test
{
protected:
    AuthorizationRequestTest() : m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials)
    {
        // EA / AA need both verification and encryption keys; EC needs only verification.
        PublicKey ea_verify = derive_public_key(generate_private_key(KeyType::NistP256));
        m_ea_encryption_key = generate_private_key(KeyType::NistP256);
        PublicKey ea_encrypt = derive_public_key(m_ea_encryption_key);
        m_ea = build_stub_certificate(ea_verify, &ea_encrypt);

        PublicKey aa_verify = derive_public_key(generate_private_key(KeyType::NistP256));
        m_aa_encryption_key = generate_private_key(KeyType::NistP256);
        PublicKey aa_encrypt = derive_public_key(m_aa_encryption_key);
        m_aa = build_stub_certificate(aa_verify, &aa_encrypt);

        m_ec_key = m_security.create_signing_key(KeyType::NistP256).value();
        m_ec = build_stub_certificate(m_security.public_key(m_ec_key).value());
    }

    AuthorizationRequestParameters make_params()
    {
        AuthorizationRequestParameters p;
        p.ec = &m_ec;
        p.ec_key = m_ec_key;
        p.ea_certificate = &m_ea;
        p.aa_certificate = &m_aa;
        p.pop_signer_key = m_security.create_signing_key(KeyType::NistP256).value();
        p.verification_key = m_security.public_key(p.pop_signer_key).value();
        p.permissions = { PsidSsp { aid::CA, { 0x01, 0x00, 0x00 } } };
        return p;
    }

    // Decode `bytes` as an EtsiTs102941Data, transparently unwrapping a POP
    // EtsiTs103097Data-Signed envelope when present (the default for AT
    // requests; TS 102 941 §6.2.3.3.1).
    bool decode_inner_management_data(const ByteBuffer& bytes,
        asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t>& mgmt) const
    {
        SignedData pop;
        if (pop.decode(bytes) && pop->content->present == Vanetza_Security_Ieee1609Dot2Content_PR_signedData) {
            const auto* sd = pop->content->choice.signedData;
            const auto& payload = sd->tbsData->payload->data->content->choice.unsecuredData;
            return mgmt.decode(payload.buf, payload.size);
        }
        return mgmt.decode(bytes.data(), bytes.size());
    }

    // AA response as specified by TS 102 941 §6.2.3.3.2: encrypted with the request's key referenced via pskRecipInfo
    EncryptedData make_response(const security::Aes128Key& key, const ByteBuffer& payload)
    {
        EncryptedData response;
        response.generate_ciphertext(m_security, key, payload);
        auto psk = asn1::allocate<Vanetza_Security_RecipientInfo_t>();
        psk->present = Vanetza_Security_RecipientInfo_PR_pskRecipInfo;
        // EncryptedData::decrypt requires a pskRecipInfo recipient but does not check its HashedId8 of the key
        copy(ByteBuffer(8, 0x00), psk->choice.pskRecipInfo);
        asn_sequence_add(&response->content->choice.encryptedData.recipients.list, psk);
        return response;
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
    PrivateKey m_ea_encryption_key;
    Certificate m_ea;
    PrivateKey m_aa_encryption_key;
    Certificate m_aa;
    Certificate m_ec;
    KeyReference m_ec_key;
};

// Empty permission list violates CertificateSubjectAttributes invariants and
// makes the request meaningless. The builder rejects it early.
TEST_F(AuthorizationRequestTest, rejects_empty_permissions)
{
    auto params = make_params();
    params.permissions.clear();
    EXPECT_THROW(build_signed_authorization_request(m_security, params), std::invalid_argument);
}

// Required certificates: ec, ea, aa. Missing any → throw.
TEST_F(AuthorizationRequestTest, rejects_missing_certificates)
{
    {
        auto params = make_params();
        params.ec = nullptr;
        EXPECT_THROW(build_signed_authorization_request(m_security, params), std::invalid_argument);
    }
    {
        auto params = make_params();
        params.ea_certificate = nullptr;
        EXPECT_THROW(build_signed_authorization_request(m_security, params), std::invalid_argument);
    }
    {
        auto params = make_params();
        params.aa_certificate = nullptr;
        EXPECT_THROW(build_authorization_request(m_security, params), std::invalid_argument);
    }
}

// With include_pop = true (default), the bytes returned are an
// EtsiTs103097Data-Signed envelope (signer = self) carrying the
// EtsiTs102941Data{authorizationRequest} as unsecuredData payload, and the
// signature verifies under the new AT verification key.
// (TS 102 941 §6.2.3.3.1 AuthorizationRequestMessageWithPop.)
TEST_F(AuthorizationRequestTest, default_includes_pop_signed_envelope)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    SignedData pop;
    ASSERT_TRUE(pop.decode(encoded));
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_signedData, pop->content->present);
    const auto& sd = *pop->content->choice.signedData;
    EXPECT_EQ(Vanetza_Security_SignerIdentifier_PR_self, sd.signer.present);
    EXPECT_EQ(aid::SCR, sd.tbsData->headerInfo.psid);

    // Signature verifies under the verification key (signer = self → empty signer cert)
    Sha256Hash digest = calculate_digest<Sha256Hash>(m_security, *sd.tbsData, nullptr);
    EXPECT_TRUE(m_security.verify(digest, make_signature(sd.signature), params.verification_key).value());
}

// With include_pop = false, the bytes returned are the bare EtsiTs102941Data
// (AuthorizationRequestMessage variant — no POP envelope).
TEST_F(AuthorizationRequestTest, opt_out_of_pop_returns_bare_management_data)
{
    auto params = make_params();
    params.include_pop = false;
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(mgmt.decode(encoded.data(), encoded.size()));
    EXPECT_EQ(Vanetza_Security_Version_v1, mgmt->version);
    EXPECT_EQ(Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest, mgmt->content.present);
}

// SharedAtRequest fields per TS 102 941 §6.2.3.3.1: eaId = HashedId8(EA),
// keyTag (16 bytes), certificateFormat = ts103097v131. With no AT
// encryption key, keyTag = first 16 bytes of HMAC-SHA256(hmacKey, verifyKey).
TEST_F(AuthorizationRequestTest, shared_at_request_fields_match_spec)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(decode_inner_management_data(encoded, mgmt));
    const auto& iar = mgmt->content.choice.authorizationRequest;
    const auto& sar = iar.sharedAtRequest;

    HashedId8 ea_hid8 = m_ea.calculate_hashed_id8(m_security);
    EXPECT_TRUE(sar.eaId == ea_hid8.octets);
    EXPECT_EQ(Vanetza_Security_CertificateFormat_ts103097v131, sar.certificateFormat);
    EXPECT_EQ(16, sar.keyTag.size);

    // Default params have no at_encryption_key; encryptionKey must be absent
    // and keyTag is HMAC over verifyKey only.
    EXPECT_EQ(nullptr, iar.publicKeys.encryptionKey);

    ByteBuffer verify_oer =
        asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &iar.publicKeys.verificationKey);
    ByteBuffer hmac_key(iar.hmacKey.buf, iar.hmacKey.buf + iar.hmacKey.size);
    EXPECT_EQ(32, hmac_key.size());
    const security::KeyTag expected_tag(
        m_security.calculate_hmac_sha256(create_byte_view(hmac_key), create_byte_view(verify_oer)).value());
    EXPECT_EQ(create_byte_view(expected_tag.octets), asn1::create_byte_view(sar.keyTag));

    ASSERT_NE(nullptr, sar.requestedSubjectAttributes.appPermissions);
    ASSERT_EQ(1, sar.requestedSubjectAttributes.appPermissions->list.count);
    EXPECT_EQ(static_cast<long>(aid::CA), sar.requestedSubjectAttributes.appPermissions->list.array[0]->psid);
}

// When at_encryption_key is provided, it appears in publicKeys and is folded
// into the keyTag HMAC input (verifyKey || encKey).
TEST_F(AuthorizationRequestTest, optional_at_encryption_key_extends_keytag)
{
    auto params = make_params();
    params.at_encryption_key = derive_public_key(generate_private_key(KeyType::NistP256));
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(decode_inner_management_data(encoded, mgmt));
    const auto& iar = mgmt->content.choice.authorizationRequest;

    ASSERT_NE(nullptr, iar.publicKeys.encryptionKey);

    ByteBuffer verify_oer =
        asn1::encode_oer(asn_DEF_Vanetza_Security_PublicVerificationKey, &iar.publicKeys.verificationKey);
    ByteBuffer enc_oer = asn1::encode_oer(asn_DEF_Vanetza_Security_PublicEncryptionKey, iar.publicKeys.encryptionKey);
    ByteBuffer combined;
    combined.insert(combined.end(), verify_oer.begin(), verify_oer.end());
    combined.insert(combined.end(), enc_oer.begin(), enc_oer.end());
    ByteBuffer hmac_key(iar.hmacKey.buf, iar.hmacKey.buf + iar.hmacKey.size);
    const security::KeyTag expected_tag(
        m_security.calculate_hmac_sha256(create_byte_view(hmac_key), create_byte_view(combined)).value());
    EXPECT_EQ(create_byte_view(expected_tag.octets), asn1::create_byte_view(iar.sharedAtRequest.keyTag));
}

// ecSignature is the privacy-preserving `encryptedEcSignature` variant; the
// inner ciphertext is addressed to the EA (recipientId = HashedId8(EA)) and decryptable by it.
TEST_F(AuthorizationRequestTest, ec_signature_is_encrypted_to_ea)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(decode_inner_management_data(encoded, mgmt));
    const auto& iar = mgmt->content.choice.authorizationRequest;
    ASSERT_EQ(Vanetza_Security_EcSignature_PR_encryptedEcSignature, iar.ecSignature.present);

    const auto& enc_sig = iar.ecSignature.choice.encryptedEcSignature;
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_encryptedData, enc_sig.content->present);
    const auto& recipients = enc_sig.content->choice.encryptedData.recipients;
    ASSERT_GE(recipients.list.count, 1);

    HashedId8 ea_hid8 = m_ea.calculate_hashed_id8(m_security);
    const auto* recip = recipients.list.array[0];
    ASSERT_EQ(Vanetza_Security_RecipientInfo_PR_certRecipInfo, recip->present);
    EXPECT_TRUE(recip->choice.certRecipInfo.recipientId == ea_hid8.octets);
    EXPECT_NO_THROW(recover_key(m_security, enc_sig, m_ea_encryption_key, m_ea));
}

// By default no validityPeriod hint is sent (TS 102 941 §6.2.3.3.1: optional).
// The AA picks the validity unilaterally.
TEST_F(AuthorizationRequestTest, default_omits_validity_period_hint)
{
    auto params = make_params();
    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(decode_inner_management_data(encoded, mgmt));
    const auto& sar = mgmt->content.choice.authorizationRequest.sharedAtRequest;
    EXPECT_EQ(nullptr, sar.requestedSubjectAttributes.validityPeriod);
}

// When `validity_period` is set, the SharedAtRequest carries a validityPeriod
// hint with the requested start (encoded as IEEE 1609.2 Time32) and duration
// (hours variant). Per CP §7.2.1, duration ≤ 1 week.
TEST_F(AuthorizationRequestTest, validity_period_hint_propagates_to_shared_at_request)
{
    auto params = make_params();
    Clock::time_point start = Clock::time_point { std::chrono::hours(24 * 7) }; // arbitrary t > epoch
    ValidityPeriodHint hint;
    hint.start = start;
    hint.duration = std::chrono::hours(168);
    params.validity_period = hint;

    ByteBuffer encoded = build_signed_authorization_request(m_security, params);

    asn1::asn1c_oer_wrapper<Vanetza_Security_EtsiTs102941Data_t> mgmt(asn_DEF_Vanetza_Security_EtsiTs102941Data);
    ASSERT_TRUE(decode_inner_management_data(encoded, mgmt));
    const auto& sar = mgmt->content.choice.authorizationRequest.sharedAtRequest;
    ASSERT_NE(nullptr, sar.requestedSubjectAttributes.validityPeriod);

    EXPECT_EQ(security::v3::convert_time32(start), sar.requestedSubjectAttributes.validityPeriod->start);
    ASSERT_EQ(Vanetza_Security_Duration_PR_hours, sar.requestedSubjectAttributes.validityPeriod->duration.present);
    EXPECT_EQ(168u, sar.requestedSubjectAttributes.validityPeriod->duration.choice.hours);
}

// build_authorization_request returns an EncryptedData addressed to the AA.
TEST_F(AuthorizationRequestTest, outer_encrypted_to_aa)
{
    auto params = make_params();
    EncryptedRequest request = build_authorization_request(m_security, params);

    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_encryptedData, request.message->content->present);
    const auto& recipients = request.message->content->choice.encryptedData.recipients;
    ASSERT_GE(recipients.list.count, 1);

    HashedId8 aa_hid8 = m_aa.calculate_hashed_id8(m_security);
    const auto* recip = recipients.list.array[0];
    ASSERT_EQ(Vanetza_Security_RecipientInfo_PR_certRecipInfo, recip->present);
    EXPECT_TRUE(recip->choice.certRecipInfo.recipientId == aa_hid8.octets);
}

// The AA recovers the request's key to encrypt its response with (TS 102 941 §6.2.3.3.2).
TEST_F(AuthorizationRequestTest, request_key_is_encrypted_for_aa)
{
    EncryptedRequest request = build_authorization_request(m_security, make_params());
    EXPECT_EQ(request.key, recover_key(m_security, *request.message, m_aa_encryption_key, m_aa));
}

TEST_F(AuthorizationRequestTest, aa_response_is_decrypted_with_request_key)
{
    EncryptedRequest request = build_authorization_request(m_security, make_params());
    const ByteBuffer payload { 0x01, 0x23, 0x45, 0x67, 0x89 };
    EncryptedData response = make_response(request.key, payload);
    EXPECT_EQ(payload, response.decrypt(m_security, request.key));
}

TEST_F(AuthorizationRequestTest, tampered_aa_response_is_decoding_failure)
{
    EncryptedRequest request = build_authorization_request(m_security, make_params());
    EncryptedData response = make_response(request.key, ByteBuffer { 0x01, 0x23, 0x45, 0x67, 0x89 });
    response->content->choice.encryptedData.ciphertext.choice.aes128ccm.ccmCiphertext.buf[0] ^= 0x01;
    EXPECT_THROW(response.decrypt(m_security, request.key), DecodingFailure);
}

} // namespace pki
} // namespace vanetza
