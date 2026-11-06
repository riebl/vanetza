#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/verify_service.hpp>
#include <gtest/gtest.h>
#include <memory>

#include "certificates.hpp"

using namespace vanetza;
using namespace vanetza::security;

namespace
{

class RejectingCertificateValidator : public v3::CertificateValidator
{
public:
    Verdict valid_for_signing(const v3::CertificateView&, ItsAid) override { return Verdict::Untrusted; }
};

class CryptoProviderVerifyServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto || !module) {
            GTEST_SKIP() << "no crypto provider or security module built in";
        }
        expected<KeyReference> key = module->create_signing_key(KeyType::NistP256);
        ASSERT_TRUE(key.has_value());
        ticket_key = *key;
        expected<PublicKey> public_key = module->public_key(ticket_key);
        ASSERT_TRUE(public_key.has_value());
        ticket = v3::make_authorization_ticket(*public_key, Clock::at("2024-08-12 11:30"));
        service = std::make_unique<v3::CryptoProviderVerifyService>(*crypto);
    }

    // DENM signed with key, its signer identifier is the signer's certificate
    v3::SecuredMessage sign_message(const v3::Certificate& signer, const KeyReference& key)
    {
        v3::SecuredMessage message = v3::SecuredMessage::with_signed_data();
        message.set_hash_id(HashAlgorithm::SHA256);
        message.set_its_aid(aid::DEN);
        message.set_generation_time(0);
        message.set_payload(ByteBuffer { 0x01, 0x02, 0x03 });
        message.set_signer_identifier(signer);
        const ByteBuffer digest =
            v3::calculate_message_hash(*crypto, HashAlgorithm::SHA256, message.signing_payload(), signer);
        const expected<Signature> signature = module->sign(digest, key);
        EXPECT_TRUE(signature.has_value());
        if (signature.has_value()) {
            message.set_signature(*signature);
        }
        return message;
    }

    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    std::unique_ptr<SecurityModule> module = create_security_module();
    KeyReference ticket_key;
    v3::Certificate ticket;
    std::unique_ptr<v3::CryptoProviderVerifyService> service;
};

} // namespace

TEST_F(CryptoProviderVerifyServiceTest, message_signed_with_certificate_is_verified)
{
    const SecuredMessage message { sign_message(ticket, ticket_key) };
    const VerifyConfirm confirm = service->verify(VerifyRequest { SecuredMessageView { message } });
    EXPECT_EQ(VerificationReport::Success, confirm.report);
    EXPECT_EQ(aid::DEN, confirm.its_aid);
    EXPECT_EQ((ByteBuffer { 0x01, 0xff, 0xff, 0xff }), confirm.permissions);
    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(ticket.calculate_digest().value(), *confirm.certificate_id);
}

TEST_F(CryptoProviderVerifyServiceTest, tampered_message_has_false_signature)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_generation_time(*message.generation_time() + 1);
    EXPECT_EQ(VerificationReport::False_Signature, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unknown_signer_digest_is_not_found)
{
    v3::CertificateCache cache;
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_signer_identifier(ticket.calculate_digest().value());
    EXPECT_EQ(VerificationReport::Signer_Certificate_Not_Found, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, cached_signer_certificate_verifies_digest_signed_message)
{
    v3::CertificateCache cache;
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    ASSERT_EQ(VerificationReport::Success, service->verify(message).report);

    // signer identifier is not covered by the signature
    message.set_signer_identifier(ticket.calculate_digest().value());
    EXPECT_EQ(VerificationReport::Success, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, signer_certificate_rejected_by_validator_is_invalid)
{
    RejectingCertificateValidator validator;
    service->use_certificate_validator(&validator);
    EXPECT_EQ(VerificationReport::Invalid_Certificate, service->verify(sign_message(ticket, ticket_key)).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unsupported_hash_algorithm_is_incompatible)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message->content->choice.signedData->hashId = Vanetza_Security_HashAlgorithm_sha384 + 1;
    EXPECT_EQ(VerificationReport::Incompatible_Protocol, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, v2_message_is_incompatible)
{
    const SecuredMessage message { v2::SecuredMessage {} };
    const VerifyConfirm confirm = service->verify(VerifyRequest { SecuredMessageView { message } });
    EXPECT_EQ(VerificationReport::Incompatible_Protocol, confirm.report);
}
