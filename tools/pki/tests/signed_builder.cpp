#include "signed_builder.hpp"
#include "asn1.hpp"
#include "certificate.hpp"
#include "hashed_id8.hpp"
#include "openssl_security_module.hpp"
#include "stub_certificate.hpp"
#include "validation.hpp"
#include <vanetza/asn1/security/SignedData.h>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/memory_credential_storage.hpp>
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
    SignedBuilderTest() :
        m_credentials(std::make_shared<security::MemoryCredentialStorage>()), m_security(m_credentials)
    {
    }

    std::shared_ptr<security::MemoryCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
    OpenSslCryptoProvider m_crypto;
};

// create_external_signed produces an EtsiTs103097Data-SignedExternalPayload
// envelope whose SignedData:
//   - tbsData.payload.extDataHash is set (not data)
//   - extDataHash carries SHA-256(external_payload) when hash_algo is SHA256
//   - signer = digest(cert) when a cert is provided
//   - signature verifies against the cert's verification key
TEST_F(SignedBuilderTest, external_signed_carries_payload_hash_and_verifies)
{
    KeyReference ec_key = m_security.create_signing_key(KeyType::NistP256).value();
    Certificate ec_cert = build_stub_certificate(m_security.public_key(ec_key).value());
    ByteBuffer payload { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

    SignedData envelope =
        create_external_signed(payload, m_security, m_crypto, ec_key, HashAlgorithm::SHA256, &ec_cert);
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
    Sha256Hash expected = m_crypto.calculate_sha256_hash(payload.data(), payload.size());
    const auto& hash_oct = sd->tbsData->payload->extDataHash->choice.sha256HashedData;
    ASSERT_EQ(32, hash_oct.size);
    EXPECT_EQ(0, std::memcmp(hash_oct.buf, expected.octets.data(), 32));

    // signer = digest, matches HashedId8(ec_cert)
    ASSERT_EQ(Vanetza_Security_SignerIdentifier_PR_digest, sd->signer.present);
    HashedId8 ec_hid8 = ec_cert.calculate_hashed_id8(m_crypto);
    EXPECT_TRUE(sd->signer.choice.digest == ec_hid8.octets);

    // signature verifies against ec_cert's verification key
    Sha256Hash digest = calculate_digest<Sha256Hash>(m_crypto, *sd->tbsData, &ec_cert.raw());
    EXPECT_TRUE(
        m_crypto.verify(digest, make_signature(sd->signature), m_security.public_key(ec_key).value()).value());
}

// unusable key of a received certificate invalidates the signed data instead of failing validation
TEST_F(SignedBuilderTest, signed_data_is_invalid_for_certificate_with_unusable_key)
{
    PublicKey unusable;
    unusable.type = KeyType::NistP256;
    unusable.compression = KeyCompression::Y0; // canonical certificates have compressed keys
    unusable.x.assign(32, 0xFF); // exceeds field prime
    Certificate cert = build_stub_certificate(unusable);

    KeyReference ec_key = m_security.create_signing_key(KeyType::NistP256).value();
    SignedData envelope =
        create_external_signed(ByteBuffer { 0xCA, 0xFE }, m_security, m_crypto, ec_key, HashAlgorithm::SHA256, &cert);
    ASSERT_EQ(Vanetza_Security_Ieee1609Dot2Content_PR_signedData, envelope->content->present);
    EXPECT_FALSE(validate(m_crypto, *envelope->content->choice.signedData, cert.raw()));
}

} // namespace pki
} // namespace vanetza
