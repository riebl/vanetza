#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/type_traits.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/tests/certificates_v3.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;

namespace
{

class RejectingCertificateValidator : public v3::CertificateValidator
{
public:
    Verdict valid_for_signing(const v3::CertificateView&, ItsAid) override { return Verdict::Untrusted; }
};

void assign(Vanetza_Security_EcdsaP256Signature_t& ecdsa, const Signature& signature)
{
    ecdsa.rSig.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    vanetza::asn1::assign(ecdsa.rSig.choice.x_only, signature.r);
    vanetza::asn1::assign(ecdsa.sSig, signature.s);
}

void assign(Vanetza_Security_EcdsaP384Signature_t& ecdsa, const Signature& signature)
{
    ecdsa.rSig.present = Vanetza_Security_EccP384CurvePoint_PR_x_only;
    vanetza::asn1::assign(ecdsa.rSig.choice.x_only, signature.r);
    vanetza::asn1::assign(ecdsa.sSig, signature.s);
}

void set_signature(v3::Certificate& certificate, const Signature& signature)
{
    vanetza::asn1::free(asn_DEF_Vanetza_Security_Signature, certificate->signature);
    certificate->signature = vanetza::asn1::allocate<v3::asn1::Signature>();
    auto& choice = certificate->signature->choice;
    switch (signature.type) {
        case KeyType::NistP256:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
            assign(choice.ecdsaNistP256Signature, signature);
            break;
        case KeyType::BrainpoolP256r1:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP256r1Signature;
            assign(choice.ecdsaBrainpoolP256r1Signature, signature);
            break;
        case KeyType::BrainpoolP384r1:
            certificate->signature->present = Vanetza_Security_Signature_PR_ecdsaBrainpoolP384r1Signature;
            assign(choice.ecdsaBrainpoolP384r1Signature, signature);
            break;
        default:
            FAIL() << "unsupported signature type";
    }
}

// x-coordinate exceeds the curve's prime, i.e. the key is no point of the curve
PublicKey unusable_public_key()
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::Y0;
    key.x.assign(32, 0xff);
    return key;
}

class CryptoProviderVerifyServiceTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto || !module) {
            GTEST_SKIP() << "no crypto provider or security module built in";
        }
        aa_key = create_key(KeyType::NistP256);
        aa = v3::make_authorization_authority(public_key(aa_key), start);
        ASSERT_TRUE(issuers.insert(aa));
        ticket_key = create_key(KeyType::NistP256);
        ticket = v3::make_authorization_ticket(public_key(ticket_key), start);
        issue(ticket, aa, aa_key);
        service = std::make_unique<CryptoProviderVerifyService>(*crypto, &issuers);
    }

    KeyReference create_key(KeyType type)
    {
        expected<KeyReference> key = module->create_signing_key(type);
        EXPECT_TRUE(key.has_value());
        if (!key.has_value()) {
            return KeyReference {};
        }
        created_keys.push_back(std::make_unique<ScopedKeyPair>(*module, *key));
        return *key;
    }

    PublicKey public_key(const KeyReference& key)
    {
        expected<PublicKey> public_key = module->public_key(key);
        EXPECT_TRUE(public_key.has_value());
        return public_key.has_value() ? *public_key : PublicKey {};
    }

    // issuer signs subject's certificate: H(H(tbs) || H(issuer certificate)) (IEEE 1609.2 clause 5.3.1.2.2)
    void issue(v3::Certificate& subject, const v3::Certificate& issuer, const KeyReference& issuer_key)
    {
        const HashAlgorithm algo = v3::specified_hash_algorithm(issuer.get_verification_key_type());
        const HashedId8 issuer_id = issuer.calculate_digest().value();
        vanetza::asn1::reset(asn_DEF_Vanetza_Security_IssuerIdentifier, &subject->issuer);
        switch (algo) {
            case HashAlgorithm::SHA256:
                subject->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
                vanetza::asn1::assign(subject->issuer.choice.sha256AndDigest, issuer_id);
                break;
            case HashAlgorithm::SHA384:
                subject->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha384AndDigest;
                vanetza::asn1::assign(subject->issuer.choice.sha384AndDigest, issuer_id);
                break;
            default:
                FAIL() << "issuer key has no hash algorithm";
        }
        const ByteBuffer tbs = vanetza::asn1::encode_oer(
            asn_DEF_Vanetza_Security_ToBeSignedCertificate, &subject->toBeSigned);
        const ByteBuffer digest = v3::calculate_message_hash(*crypto, algo, tbs, issuer);
        const expected<Signature> signature = module->sign(digest, issuer_key);
        ASSERT_TRUE(signature.has_value());
        set_signature(subject, *signature);
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
    // discards created keys before their module is destroyed, e.g. persistent keys of PSA
    std::vector<std::unique_ptr<ScopedKeyPair>> created_keys;
    const Clock::time_point start = Clock::at("2024-08-12 11:30");
    v3::IssuerMemoryLookup issuers;
    KeyReference aa_key;
    v3::Certificate aa;
    KeyReference ticket_key;
    v3::Certificate ticket;
    std::unique_ptr<CryptoProviderVerifyService> service;
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

TEST_F(CryptoProviderVerifyServiceTest, ticket_of_sha384_issuer_is_verified)
{
    const KeyReference key = create_key(KeyType::BrainpoolP384r1);
    const v3::Certificate authority = v3::make_authorization_authority(public_key(key), start);
    ASSERT_TRUE(issuers.insert(authority));
    issue(ticket, authority, key);
    EXPECT_EQ(VerificationReport::Success, service->verify(sign_message(ticket, ticket_key)).report);
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_of_unknown_issuer_is_rejected)
{
    v3::IssuerMemoryLookup no_issuers;
    CryptoProviderVerifyService verifier { *crypto, &no_issuers };
    const VerifyConfirm confirm = verifier.verify(sign_message(ticket, ticket_key));
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_is_accepted_without_issuers)
{
    CryptoProviderVerifyService verifier { *crypto, nullptr };
    const v3::Certificate unissued = v3::make_authorization_ticket(public_key(ticket_key), start);
    EXPECT_EQ(VerificationReport::Success, verifier.verify(sign_message(unissued, ticket_key)).report);
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_modified_after_issuing_is_rejected)
{
    ticket.add_app_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    const VerifyConfirm confirm = service->verify(sign_message(ticket, ticket_key));
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_without_signature_is_rejected)
{
    vanetza::asn1::free(asn_DEF_Vanetza_Security_Signature, ticket->signature);
    ticket->signature = nullptr;
    const VerifyConfirm confirm = service->verify(sign_message(ticket, ticket_key));
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Missing_Signature, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, self_signed_ticket_is_rejected)
{
    vanetza::asn1::reset(asn_DEF_Vanetza_Security_IssuerIdentifier, &ticket->issuer);
    ticket->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
    ticket->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
    const VerifyConfirm confirm = service->verify(sign_message(ticket, ticket_key));
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, cached_ticket_of_untrusted_issuer_is_rejected)
{
    v3::CertificateCache cache;
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    ASSERT_EQ(VerificationReport::Success, service->verify(message).report);

    // issuer is not trusted anymore, e.g. revoked meanwhile
    v3::IssuerMemoryLookup no_issuers;
    CryptoProviderVerifyService verifier { *crypto, &no_issuers };
    verifier.use_certificate_cache(&cache);
    message.set_signer_identifier(ticket.calculate_digest().value());
    const VerifyConfirm confirm = verifier.verify(message);
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_of_falsely_signed_message_is_not_cached)
{
    v3::CertificateCache cache;
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_generation_time(*message.generation_time() + 1);
    ASSERT_EQ(VerificationReport::False_Signature, service->verify(message).report);
    EXPECT_EQ(nullptr, cache.lookup(ticket.calculate_digest().value()));
}

TEST_F(CryptoProviderVerifyServiceTest, unusable_signer_key_is_invalid_certificate)
{
    CryptoProviderVerifyService verifier { *crypto, nullptr };
    const v3::Certificate unusable = v3::make_authorization_ticket(unusable_public_key(), start);
    EXPECT_EQ(VerificationReport::Invalid_Certificate, verifier.verify(sign_message(unusable, ticket_key)).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unusable_issuer_key_is_configuration_problem)
{
    const v3::Certificate unusable = v3::make_authorization_authority(unusable_public_key(), start);
    ASSERT_TRUE(issuers.insert(unusable));
    issue(ticket, unusable, aa_key);
    EXPECT_EQ(VerificationReport::Configuration_Problem, service->verify(sign_message(ticket, ticket_key)).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unsupported_issuer_identifier_is_incompatible)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    const auto included = boost::get<const v3::asn1::Certificate*>(message.signer_identifier());
    auto& issuer = const_cast<v3::asn1::Certificate*>(included)->issuer;
    vanetza::asn1::reset(asn_DEF_Vanetza_Security_IssuerIdentifier, &issuer);
    issuer.present = Vanetza_Security_IssuerIdentifier_PR_NOTHING;
    EXPECT_EQ(VerificationReport::Incompatible_Protocol, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unencodable_message_is_incompatible)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    auto& header = message->content->choice.signedData->tbsData->headerInfo;
    header.p2pcdLearningRequest = vanetza::asn1::allocate<Vanetza_Security_HashedId3_t>();
    // HashedId3 has exactly three octets
    vanetza::asn1::assign(*header.p2pcdLearningRequest, ByteBuffer { 0x01, 0x02 });
    EXPECT_EQ(VerificationReport::Incompatible_Protocol, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unencodable_ticket_is_incompatible)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    const auto included = boost::get<const v3::asn1::Certificate*>(message.signer_identifier());
    auto& craca_id = const_cast<v3::asn1::Certificate*>(included)->toBeSigned.cracaId;
    // HashedId3 has exactly three octets
    vanetza::asn1::assign(craca_id, ByteBuffer { 0x01, 0x02 });
    EXPECT_EQ(VerificationReport::Incompatible_Protocol, service->verify(message).report);
}
