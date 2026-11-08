#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/credential_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/static_credential_provider.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>
#include <memory>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

SignRequest make_denm_request()
{
    SignRequest request;
    ChunkPacket packet;
    packet[OsiLayer::Application] = ByteBuffer { 0x01, 0x02, 0x03 };
    request.plain_message = std::move(packet);
    request.its_aid = aid::DEN;
    return request;
}

v2::Certificate make_certificate(v2::SubjectType type)
{
    v2::Certificate certificate;
    certificate.subject_info.subject_type = type;
    // calculate_hash serializes the signature, its r and s need 32 octets (NIST P-256)
    certificate.signature = EcdsaSignature { X_Coordinate_Only { ByteBuffer(32, 0x00) }, ByteBuffer(32, 0x00) };
    return certificate;
}

class NoCredentialProvider : public v2::CredentialProvider
{
public:
    const v2::Credential* signing_credential(ItsAid) override { return nullptr; }
};

class SecurityModuleSignServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!module || !crypto) {
            GTEST_SKIP() << "no security module or crypto provider built in";
        }
    }

    StoredPositionProvider positioning;
    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    std::unique_ptr<SecurityModule> module = create_security_module();
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    v2::DefaultSignHeaderPolicy policy { runtime, positioning };
    const v2::Certificate ticket = make_certificate(v2::SubjectType::Authorization_Ticket);
    const v2::Certificate authority = make_certificate(v2::SubjectType::Authorization_Authority);
};

} // namespace

TEST_F(SecurityModuleSignServiceTest, message_is_signed_with_credential_key)
{
    expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    ScopedKeyPair key_pair { *module, *key };
    expected<PublicKey> public_key = module->public_key(*key);
    ASSERT_TRUE(public_key.has_value());
    v2::StaticCredentialProvider credentials { ticket, authority, *key };
    v2::SecurityModuleSignService sign_service { *module, *crypto, credentials, policy };

    SignConfirm sign_confirm = sign_service.sign(make_denm_request());
    ASSERT_TRUE(sign_confirm.secured_message);
    const v2::SecuredMessage* message = boost::get<v2::SecuredMessage>(&*sign_confirm.secured_message);
    ASSERT_NE(nullptr, message);
    // DENM names its signer by the credential's full certificate
    const v2::SignerInfo* signer = message->header_field<v2::HeaderFieldType::Signer_Info>();
    ASSERT_NE(nullptr, signer);
    const v2::Certificate* signer_certificate = boost::get<v2::Certificate>(signer);
    ASSERT_NE(nullptr, signer_certificate);
    EXPECT_EQ(v2::calculate_hash(ticket), v2::calculate_hash(*signer_certificate));
    const v2::Signature* signature = boost::get<v2::Signature>(message->trailer_field(v2::TrailerFieldType::Signature));
    ASSERT_NE(nullptr, signature);
    const boost::optional<EcdsaSignature> ecdsa = v2::extract_ecdsa_signature(*signature);
    ASSERT_TRUE(ecdsa);

    // signature covers message including its trailer fields, its r is the x-coordinate of R
    const ByteBuffer payload = v2::convert_for_signing(*message, message->trailer_fields);
    const Sha256Hash digest = crypto->calculate_sha256_hash(payload.data(), payload.size());
    const Signature payload_signature { convert_for_signing(ecdsa->R), ecdsa->s, KeyType::NistP256 };
    EXPECT_TRUE(crypto->verify(digest, payload_signature, *public_key).value());
}

TEST_F(SecurityModuleSignServiceTest, message_without_credential_is_not_signed)
{
    NoCredentialProvider credentials;
    v2::SecurityModuleSignService sign_service { *module, *crypto, credentials, policy };

    SignConfirm sign_confirm = sign_service.sign(make_denm_request());
    EXPECT_FALSE(sign_confirm.secured_message);
    EXPECT_EQ(SignConfirmError::No_Certificate, sign_confirm.error);
}

TEST_F(SecurityModuleSignServiceTest, signing_failure_is_reported)
{
    // the module cannot sign with an empty key reference
    v2::StaticCredentialProvider credentials { ticket, authority, KeyReference {} };
    v2::SecurityModuleSignService sign_service { *module, *crypto, credentials, policy };

    SignConfirm sign_confirm = sign_service.sign(make_denm_request());
    EXPECT_FALSE(sign_confirm.secured_message);
    EXPECT_EQ(SignConfirmError::Unspecified, sign_confirm.error);
}
