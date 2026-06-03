#include "ea_response.hpp"
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
#include <vanetza/asn1/security/EnrolmentResponseCode.h>
#include <vanetza/asn1/security/EtsiTs102941Data.h>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>
#include <vanetza/asn1/security/Ieee1609Dot2Data.h>
#include <vanetza/asn1/security/InnerEcResponse.h>
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

// Builder for a decrypted enrolment response. Defaults produce a structurally
// valid response with code=ok and a synthetic EC certificate. Each knob
// switches one invariant off so tests can assert the parser rejects it.
struct ResponseBuilder
{
    OpenSslSecurityModule* security;
    const Certificate* ea_cert;
    const PublicKey* ea_signing_key;

    // Knobs
    Vanetza_Security_EnrolmentResponseCode_t code = Vanetza_Security_EnrolmentResponseCode_ok;
    bool include_certificate = true;
    boost::optional<long> psid_override;
    // NOTHING = use the correct `digest` variant; other values force that variant
    Vanetza_Security_SignerIdentifier_PR signer_variant = Vanetza_Security_SignerIdentifier_PR_NOTHING;
    // if set, forces the digest bytes placed in signer.digest (overriding the
    // correct EA HashedId8). Only consulted when signer_variant is `digest`
    // or NOTHING (digest default).
    boost::optional<HashedId8> signer_digest_override;
    bool corrupt_signature = false;
    // if true, wrap the final payload as unsecuredData instead of signedData
    bool outer_as_unsecured = false;

    ByteBuffer build() const
    {
        // inner: EtsiTs102941Data { enrolmentResponse { InnerEcResponse } }
        MgmtData inner;
        inner->version = Vanetza_Security_Version_v1;
        inner->content.present = Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse;
        auto& ec_resp = inner->content.choice.enrolmentResponse;
        // 16-byte requestHash (SHA-256 prefix in the real flow)
        uint8_t req_hash[16];
        std::fill(std::begin(req_hash), std::end(req_hash), 0xAB);
        OCTET_STRING_fromBuf(&ec_resp.requestHash, reinterpret_cast<char*>(req_hash), 16);
        ec_resp.responseCode = code;
        if (include_certificate) {
            // Synthesize a dummy EC cert. Not cryptographically valid, just
            // OER-encodable, so the parser can decode it and the test can
            // check it came through intact.
            PublicKey dummy_key = security->create_key(KeyType::NistP256);
            Certificate dummy_ec = build_stub_certificate(dummy_key);
            ByteBuffer encoded_ec = dummy_ec.encode();
            void* decoded = nullptr;
            EXPECT_TRUE(asn1::decode_oer(asn_DEF_Vanetza_Security_EtsiTs103097Certificate, &decoded, encoded_ec));
            // InnerEcResponse.certificate is a pointer to the shim struct; the decoded layout is bit-compatible.
            ec_resp.certificate = static_cast<Vanetza_Security_EtsiTs103097Certificate*>(decoded);
        }
        EXPECT_TRUE(inner.validate());
        ByteBuffer inner_encoded = inner.encode();

        // outer: EtsiTs103097Data { signedData or unsecuredData }
        asn1::asn1c_oer_wrapper<Vanetza_Security_Ieee1609Dot2Data_t> outer(asn_DEF_Vanetza_Security_Ieee1609Dot2Data);
        outer->protocolVersion = protocol_version;
        outer->content = asn1::allocate<Vanetza_Security_Ieee1609Dot2Content_t>();

        if (outer_as_unsecured) {
            outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_unsecuredData;
            copy(inner_encoded, outer->content->choice.unsecuredData);
            return outer.encode();
        }

        outer->content->present = Vanetza_Security_Ieee1609Dot2Content_PR_signedData;
        outer->content->choice.signedData = asn1::allocate<Vanetza_Security_SignedData_t>();
        auto& sd = *outer->content->choice.signedData;
        sd.hashId = Vanetza_Security_HashAlgorithm_sha256;

        // signer
        const auto variant = (signer_variant == Vanetza_Security_SignerIdentifier_PR_NOTHING) ?
                                 Vanetza_Security_SignerIdentifier_PR_digest :
                                 signer_variant;
        sd.signer.present = variant;
        if (variant == Vanetza_Security_SignerIdentifier_PR_digest) {
            HashedId8 ea_hid8 = ea_cert->calculate_hashed_id8(*security);
            if (signer_digest_override) {
                ea_hid8 = *signer_digest_override;
            }
            OCTET_STRING_fromBuf(&sd.signer.choice.digest, reinterpret_cast<const char*>(ea_hid8.octets.data()), 8);
        }

        // tbsData
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

        // signature
        const Vanetza_Security_Certificate_t* signer_cert_for_hash =
            (variant == Vanetza_Security_SignerIdentifier_PR_self) ? nullptr : &ea_cert->raw();
        Sha256Hash digest = calculate_digest<Sha256Hash>(*security, *sd.tbsData, signer_cert_for_hash);
        auto signature = security->sign(ByteBuffer { digest.octets.begin(), digest.octets.end() }, *ea_signing_key);
        EXPECT_TRUE(static_cast<bool>(signature));

        sd.signature.present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
        sd.signature.choice.ecdsaNistP256Signature.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
        copy_left_padded(signature->r, sd.signature.choice.ecdsaNistP256Signature.rSig.choice.x_only, 32);
        copy_left_padded(signature->s, sd.signature.choice.ecdsaNistP256Signature.sSig, 32);

        if (corrupt_signature) {
            // Flip one byte in the encoded signature after we've laid it down.
            // Easiest: perturb sSig in place.
            auto& s_oct = sd.signature.choice.ecdsaNistP256Signature.sSig;
            if (s_oct.size > 0) {
                s_oct.buf[0] ^= 0xFF;
            }
        }

        return outer.encode();
    }
};

} // namespace

class EnrolmentResponseTest : public ::testing::Test
{
protected:
    EnrolmentResponseTest() :
        m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials),
        m_ea_key(m_security.create_key(KeyType::NistP256)), m_ea_certificate(build_stub_certificate(m_ea_key))
    {
    }

    ResponseBuilder builder()
    {
        return ResponseBuilder { &m_security, &m_ea_certificate, &m_ea_key };
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
    PublicKey m_ea_key;
    Certificate m_ea_certificate;
};

// Happy path: a properly EA-signed response with code=ok and a certificate
// round-trips into an EnrolmentResponse whose fields match what went in.
TEST_F(EnrolmentResponseTest, happy_path_returns_code_ok_and_certificate)
{
    ByteBuffer payload = builder().build();

    EnrolmentResponse resp = parse_enrolment_response(m_security, payload, m_ea_certificate);

    EXPECT_EQ(Vanetza_Security_EnrolmentResponseCode_ok, resp.code);
    ASSERT_TRUE(resp.certificate.has_value());
    EXPECT_EQ(16u, resp.request_hash.size());
}

// The parser must reject random bytes that do not decode as Ieee1609Dot2Data.
TEST_F(EnrolmentResponseTest, rejects_undecodable_input)
{
    ByteBuffer garbage(16, 0xFF);
    EXPECT_THROW(parse_enrolment_response(m_security, garbage, m_ea_certificate), DecodingFailure);
}

// The outer content must be signedData: unsecuredData is not acceptable for
// an enrolment response.
TEST_F(EnrolmentResponseTest, rejects_outer_unsecured_data)
{
    ResponseBuilder b = builder();
    b.outer_as_unsecured = true;
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), DecodingFailure);
}

// TS 102 941 §6.2.3.2.2: the outer signer shall be `digest` naming the EA.
// A `self` signer (e.g. accidentally replaying a request shape) is rejected.
TEST_F(EnrolmentResponseTest, rejects_self_signer)
{
    ResponseBuilder b = builder();
    b.signer_variant = Vanetza_Security_SignerIdentifier_PR_self;
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), DecodingFailure);
}

// The signer's digest must match HashedId8(ea_certificate). A mismatch means
// the response was signed by someone else — must be rejected.
TEST_F(EnrolmentResponseTest, rejects_signer_digest_mismatch)
{
    ResponseBuilder b = builder();
    HashedId8 other;
    other.octets = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    b.signer_digest_override = other;
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), VerificationFailure);
}

// TS 102 941 §6.2.3.2.2: the outer tbsData.headerInfo.psid shall be SCR.
TEST_F(EnrolmentResponseTest, rejects_wrong_psid)
{
    ResponseBuilder b = builder();
    b.psid_override = 0x20; // arbitrary non-SCR
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), DecodingFailure);
}

// A signature that does not verify against the EA certificate must be
// rejected — even when all structural fields match.
TEST_F(EnrolmentResponseTest, rejects_bad_signature)
{
    ResponseBuilder b = builder();
    b.corrupt_signature = true;
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), VerificationFailure);
}

// A non-ok response code is not a structural failure; the parser returns it
// to the caller so initial and renewal flows can treat it differently.
// (Current initial flow will still throw on non-ok, but that's a caller
// policy, not a parser one.)
TEST_F(EnrolmentResponseTest, non_ok_code_returns_without_throwing)
{
    ResponseBuilder b = builder();
    b.code = Vanetza_Security_EnrolmentResponseCode_deniedpermissions;
    b.include_certificate = false;
    ByteBuffer payload = b.build();

    EnrolmentResponse resp = parse_enrolment_response(m_security, payload, m_ea_certificate);

    EXPECT_EQ(Vanetza_Security_EnrolmentResponseCode_deniedpermissions, resp.code);
    EXPECT_FALSE(resp.certificate.has_value());
}

// Code=ok but no certificate violates TS 102 941 — parser must reject.
TEST_F(EnrolmentResponseTest, rejects_ok_without_certificate)
{
    ResponseBuilder b = builder();
    b.code = Vanetza_Security_EnrolmentResponseCode_ok;
    b.include_certificate = false;
    ByteBuffer payload = b.build();

    EXPECT_THROW(parse_enrolment_response(m_security, payload, m_ea_certificate), DecodingFailure);
}

} // namespace pki
} // namespace vanetza
