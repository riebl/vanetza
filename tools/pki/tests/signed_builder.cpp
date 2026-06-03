#include "signed_builder.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "stub_certificate.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/SignedData.h>
#include <vanetza/common/byte_buffer.hpp>
#include <gtest/gtest.h>
#include <cstring>
#include <memory>

namespace vanetza
{
namespace pki
{

class SignedBuilderTest : public ::testing::Test
{
protected:
    SignedBuilderTest() : m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials)
    {
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
};

// create_external_signed produces an EtsiTs103097Data-SignedExternalPayload
// envelope whose SignedData:
//   - tbsData.payload.extDataHash is set (not data)
//   - extDataHash carries SHA-256(external_payload) when hash_algo is SHA256
//   - signer = digest(cert) when a cert is provided
//   - signature verifies against the cert's verification key
TEST_F(SignedBuilderTest, external_signed_carries_payload_hash_and_verifies)
{
    PublicKey ec_key = m_security.create_key(KeyType::NistP256);
    Certificate ec_cert = build_stub_certificate(ec_key);
    ByteBuffer payload { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

    SignedData envelope = create_external_signed(payload, m_security, ec_key, HashAlgorithm::SHA256, &ec_cert);
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_signedData, envelope->content->present);
    Vanetza_Security_SignedData_t* sd = envelope->content->choice.signedData;
    ASSERT_NE(nullptr, sd);

    // payload.extDataHash present, payload.data absent
    ASSERT_NE(nullptr, sd->tbsData);
    ASSERT_NE(nullptr, sd->tbsData->payload);
    ASSERT_NE(nullptr, sd->tbsData->payload->extDataHash);
    EXPECT_EQ(nullptr, sd->tbsData->payload->data);
    ASSERT_EQ(Vanetza_Security_HashedData_PR_sha256HashedData, sd->tbsData->payload->extDataHash->present);

    // hash equals SHA-256(payload)
    Sha256Hash expected = m_security.calculate_sha256_hash(payload.data(), payload.size());
    const auto& hash_oct = sd->tbsData->payload->extDataHash->choice.sha256HashedData;
    ASSERT_EQ(32, hash_oct.size);
    EXPECT_EQ(0, std::memcmp(hash_oct.buf, expected.octets.data(), 32));

    // signer = digest, matches HashedId8(ec_cert)
    ASSERT_EQ(Vanetza_Security_SignerIdentifier_PR_digest, sd->signer.present);
    HashedId8 ec_hid8 = ec_cert.calculate_hashed_id8(m_security);
    EXPECT_TRUE(sd->signer.choice.digest == ec_hid8.octets);

    // signature verifies against ec_cert's verification key
    Sha256Hash digest = calculate_digest<Sha256Hash>(m_security, *sd->tbsData, &ec_cert.raw());
    EXPECT_TRUE(m_security.verify(digest, make_signature(sd->signature), ec_key));
}

} // namespace pki
} // namespace vanetza
