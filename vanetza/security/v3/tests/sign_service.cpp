#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v3/basic_elements.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/static_credential_provider.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

// authorization ticket of a public key, its issuer is fictitious because these tests validate no certificate chain
v3::Certificate make_authorization_ticket(const PublicKey& key, Clock::time_point start)
{
    v3::Certificate ticket;
    ticket->version = 3;
    ticket->type = Vanetza_Security_CertificateType_explicit;
    ticket->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    const std::array<std::uint8_t, 8> issuer_digest = { 1, 2, 3, 4, 5, 6, 7, 8 };
    asn1::assign(ticket->issuer.choice.sha256AndDigest, issuer_digest);
    ticket->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    const std::array<std::uint8_t, 3> craca_id = { 0, 0, 0 };
    asn1::assign(ticket->toBeSigned.cracaId, craca_id);
    ticket->toBeSigned.crlSeries = 0;
    ticket->toBeSigned.validityPeriod.start = v3::convert_time32(start);
    ticket->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_hours;
    ticket->toBeSigned.validityPeriod.duration.choice.hours = 168;

    auto& indicator = ticket->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    indicator.choice.verificationKey.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;
    auto& point = indicator.choice.verificationKey.choice.ecdsaNistP256;
    OCTET_STRING_t* x = nullptr;
    if (key.compression == KeyCompression::Y0) {
        point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
        x = &point.choice.compressed_y_0;
    } else {
        point.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_1;
        x = &point.choice.compressed_y_1;
    }
    asn1::assign(*x, key.x);

    ticket.add_app_permission(aid::DEN, ByteBuffer({ 1, 0xff, 0xff, 0xff }));
    return ticket;
}

SignRequest make_denm_request()
{
    SignRequest request;
    ChunkPacket packet;
    packet[OsiLayer::Application] = ByteBuffer {0x01, 0x02, 0x03};
    request.plain_message = std::move(packet);
    request.its_aid = aid::DEN;
    return request;
}

class SecurityModuleSignServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!module || !crypto) {
            GTEST_SKIP() << "no security module or crypto provider built in";
        }
    }

    StoredPositionProvider position_provider;
    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    std::unique_ptr<SecurityModule> module = create_security_module();
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    v3::CertificateCache cache;
    v3::DefaultSignHeaderPolicy sign_header_policy { runtime, position_provider, cache };
    v3::NullCertificateValidator cert_validator;
};

} // namespace

TEST_F(SecurityModuleSignServiceTest, message_is_signed_with_credential_key)
{
    expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    expected<PublicKey> public_key = module->public_key(*key);
    ASSERT_TRUE(public_key.has_value());
    const v3::Certificate ticket = make_authorization_ticket(*public_key, runtime.now());
    v3::StaticCredentialProvider credentials { ticket, *key };
    v3::SecurityModuleSignService sign_service { *module, *crypto, credentials, sign_header_policy, cert_validator };

    SignConfirm sign_confirm = sign_service.sign(make_denm_request());
    ASSERT_TRUE(sign_confirm.secured_message);
    const v3::SecuredMessage* message = boost::get<v3::SecuredMessage>(&*sign_confirm.secured_message);
    ASSERT_NE(nullptr, message);
    boost::optional<Signature> signature = message->signature();
    ASSERT_TRUE(signature);

    // signature covers hash of payload and signer certificate (IEEE 1609.2 5.3.1.2.2)
    const ByteBuffer digest = v3::calculate_message_hash(
        *crypto, message->hash_id(), message->signing_payload(), v3::CertificateView { ticket });
    Sha256Hash expected_digest;
    ASSERT_EQ(expected_digest.octets.size(), digest.size());
    std::copy(digest.begin(), digest.end(), expected_digest.octets.begin());
    EXPECT_TRUE(crypto->verify(expected_digest, *signature, *public_key).value());
}

TEST_F(SecurityModuleSignServiceTest, message_without_ticket_permission_is_not_signed)
{
    expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    expected<PublicKey> public_key = module->public_key(*key);
    ASSERT_TRUE(public_key.has_value());
    // ticket permits DENM but not CAM
    v3::StaticCredentialProvider credentials { make_authorization_ticket(*public_key, runtime.now()), *key };
    v3::SecurityModuleSignService sign_service { *module, *crypto, credentials, sign_header_policy, cert_validator };

    SignRequest request = make_denm_request();
    request.its_aid = aid::CA;
    SignConfirm sign_confirm = sign_service.sign(std::move(request));
    EXPECT_FALSE(sign_confirm.secured_message);
    EXPECT_EQ(SignConfirmError::No_Certificate, sign_confirm.error);
}

TEST_F(SecurityModuleSignServiceTest, signing_failure_is_reported)
{
    expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    expected<PublicKey> public_key = module->public_key(*key);
    ASSERT_TRUE(public_key.has_value());
    // the module cannot sign with an empty key reference
    const v3::Certificate ticket = make_authorization_ticket(*public_key, runtime.now());
    v3::StaticCredentialProvider credentials { ticket, KeyReference {} };
    v3::SecurityModuleSignService sign_service { *module, *crypto, credentials, sign_header_policy, cert_validator };

    SignConfirm sign_confirm = sign_service.sign(make_denm_request());
    EXPECT_FALSE(sign_confirm.secured_message);
    EXPECT_EQ(SignConfirmError::Unspecified, sign_confirm.error);
}
