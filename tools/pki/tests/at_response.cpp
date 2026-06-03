#include "at_response.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "exception.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "stub_certificate.hpp"
#include "time.hpp"
#include "validation.hpp"
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/AuthorizationResponseCode.h>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/asn1/security/Ieee1609Dot2Data.h>
#include <vanetza/asn1/security/InnerAtResponse.h>
#include <vanetza/asn1/security/SignedData.h>
#include <vanetza/asn1/security/Time64.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <gtest/gtest.h>
#include <memory>

namespace vanetza
{
namespace pki
{
namespace
{

constexpr std::uint8_t protocol_version = 3;

// Builder for a decrypted authorization response. Defaults produce a valid
// response with code=ok and a synthetic AT certificate. Knobs flip individual
// invariants for negative tests.
struct AtResponseBuilder
{
    OpenSslSecurityModule* security;
    const Certificate* aa_cert;
    const PublicKey* aa_signing_key;

    Vanetza_Security_AuthorizationResponseCode_t code = Vanetza_Security_AuthorizationResponseCode_ok;
    bool include_certificate = true;
    boost::optional<long> psid_override;
    boost::optional<HashedId8> signer_digest_override;

    ByteBuffer build() const
    {
        // Inner: EtsiTs102941Data { authorizationResponse { InnerAtResponse } }
        MgmtData inner;
        inner->version = Vanetza_Security_Version_v1;
        inner->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse;
        auto& at_resp = inner->content.choice.authorizationResponse;

        uint8_t req_hash[16];
        std::fill(std::begin(req_hash), std::end(req_hash), 0xCD);
        OCTET_STRING_fromBuf(&at_resp.requestHash, reinterpret_cast<char*>(req_hash), 16);
        at_resp.responseCode = code;
        if (include_certificate) {
            PublicKey dummy_key = security->create_key(KeyType::NistP256);
            Certificate dummy_at = build_stub_certificate(dummy_key);
            ByteBuffer encoded_at = dummy_at.encode();
            void* decoded = nullptr;
            EXPECT_TRUE(asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &decoded, encoded_at));
            at_resp.certificate = static_cast<Vanetza_Security_EtsiTs103097Certificate*>(decoded);
        }
        EXPECT_TRUE(inner.validate());
        ByteBuffer inner_encoded = inner.encode();

        // Outer: EtsiTs103097Data { signedData (signer=digest(AA)) }
        asn1::asn1c_oer_wrapper<Vanetza_Security_Ieee1609Dot2Data_t> outer(asn_DEF_Vanetza_Security_Ieee1609Dot2Data);
        outer->protocolVersion = protocol_version;
        outer->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;
        outer->content->choice.signedData = asn1::allocate<Vanetza_Security_SignedData_t>();
        auto& sd = *outer->content->choice.signedData;
        sd.hashId = Vanetza_Security_HashAlgorithm_sha256;

        sd.signer.present = Vanetza_Security_SignerIdentifier_PR_digest;
        HashedId8 aa_hid8 = signer_digest_override.value_or(aa_cert->calculate_hashed_id8(*security));
        OCTET_STRING_fromBuf(&sd.signer.choice.digest, reinterpret_cast<const char*>(aa_hid8.octets.data()), 8);

        sd.tbsData = asn1::allocate<Vanetza_Security_ToBeSignedData_t>();
        sd.tbsData->headerInfo.psid = psid_override.value_or(aid::SCR);
        sd.tbsData->headerInfo.generationTime = asn1::allocate<Vanetza_Security_Time64_t>();
        asn_uint642INTEGER(sd.tbsData->headerInfo.generationTime, security::v3::convert_time64(current_time()));

        sd.tbsData->payload = asn1::allocate<Vanetza_Security_SignedDataPayload_t>();
        auto* sdp = sd.tbsData->payload;
        sdp->data = asn1::allocate<Vanetza_Security_EtsiTs103097Data_t>();
        sdp->data->protocolVersion = protocol_version;
        sdp->data->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();
        sdp->data->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
        copy(inner_encoded, sdp->data->content->choice.unsecuredData);

        Sha256Hash digest = calculate_digest<Sha256Hash>(*security, *sd.tbsData, &aa_cert->raw());
        auto signature = security->sign(ByteBuffer { digest.octets.begin(), digest.octets.end() }, *aa_signing_key);
        EXPECT_TRUE(static_cast<bool>(signature));

        sd.signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
        sd.signature.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
        copy_left_padded(signature->r, sd.signature.choice.ecdsaNistP256Signature.rSig.choice.x_only, 32);
        copy_left_padded(signature->s, sd.signature.choice.ecdsaNistP256Signature.sSig, 32);

        return outer.encode();
    }
};

} // namespace

class AuthorizationResponseTest : public ::testing::Test
{
protected:
    AuthorizationResponseTest() :
        m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials),
        m_aa_key(m_security.create_key(KeyType::NistP256)), m_aa_certificate(build_stub_certificate(m_aa_key))
    {
    }

    AtResponseBuilder builder()
    {
        return AtResponseBuilder { &m_security, &m_aa_certificate, &m_aa_key };
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
    PublicKey m_aa_key;
    Certificate m_aa_certificate;
};

TEST_F(AuthorizationResponseTest, happy_path_returns_code_ok_and_certificate)
{
    ByteBuffer payload = builder().build();
    AuthorizationResponse resp = parse_authorization_response(m_security, payload, m_aa_certificate);
    EXPECT_EQ(Vanetza_Security_AuthorizationResponseCode_ok, resp.code);
    ASSERT_TRUE(resp.certificate.has_value());
    EXPECT_EQ(16u, resp.request_hash.size());
}

TEST_F(AuthorizationResponseTest, rejects_signer_digest_mismatch)
{
    AtResponseBuilder b = builder();
    HashedId8 other;
    other.octets = { 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22 };
    b.signer_digest_override = other;
    ByteBuffer payload = b.build();
    EXPECT_THROW(parse_authorization_response(m_security, payload, m_aa_certificate), VerificationFailure);
}

TEST_F(AuthorizationResponseTest, rejects_wrong_psid)
{
    AtResponseBuilder b = builder();
    b.psid_override = 0x20; // arbitrary non-SCR
    ByteBuffer payload = b.build();
    EXPECT_THROW(parse_authorization_response(m_security, payload, m_aa_certificate), DecodingFailure);
}

TEST_F(AuthorizationResponseTest, non_ok_code_returns_without_throwing)
{
    AtResponseBuilder b = builder();
    b.code = Vanetza_Security_AuthorizationResponseCode_deniedpermissions;
    b.include_certificate = false;
    ByteBuffer payload = b.build();
    AuthorizationResponse resp = parse_authorization_response(m_security, payload, m_aa_certificate);
    EXPECT_EQ(Vanetza_Security_AuthorizationResponseCode_deniedpermissions, resp.code);
    EXPECT_FALSE(resp.certificate.has_value());
}

TEST_F(AuthorizationResponseTest, rejects_ok_without_certificate)
{
    AtResponseBuilder b = builder();
    b.code = Vanetza_Security_AuthorizationResponseCode_ok;
    b.include_certificate = false;
    ByteBuffer payload = b.build();
    EXPECT_THROW(parse_authorization_response(m_security, payload, m_aa_certificate), DecodingFailure);
}

} // namespace pki
} // namespace vanetza
