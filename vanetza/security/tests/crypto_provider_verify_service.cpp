#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/type_traits.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/tests/certificates_v3.hpp>
#include <vanetza/security/tests/null_crypto_provider.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/null_certificate_validator.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/static_certificate_provider.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>
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
        service = std::make_unique<CryptoProviderVerifyService>(runtime, *crypto, positioning);
        service->use_issuer_lookup(&issuers);
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
        const HashedId8 issuer_id = issuer.calculate_digest(*crypto).value();
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

    // message signed with key, a DENM by default, its signer identifier is the signer's certificate
    v3::SecuredMessage sign_message(const v3::Certificate& signer, const KeyReference& key, ItsAid its_aid = aid::DEN)
    {
        v3::SecuredMessage message = v3::SecuredMessage::with_signed_data();
        message.set_hash_id(HashAlgorithm::SHA256);
        message.set_its_aid(its_aid);
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
    ManualRuntime runtime { start };
    StoredPositionProvider positioning;
    v3::IssuerMemoryLookup issuers { crypto ? *crypto : NullCryptoProvider::instance() };
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
    EXPECT_EQ(ticket.calculate_digest(*crypto).value(), *confirm.certificate_id);
}

TEST_F(CryptoProviderVerifyServiceTest, tampered_message_has_false_signature)
{
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_generation_time(*message.generation_time() + 1);
    EXPECT_EQ(VerificationReport::False_Signature, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, unknown_signer_digest_is_not_found)
{
    v3::CertificateCache cache { *crypto };
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_signer_identifier(ticket.calculate_digest(*crypto).value());
    EXPECT_EQ(VerificationReport::Signer_Certificate_Not_Found, service->verify(message).report);
}

TEST_F(CryptoProviderVerifyServiceTest, cached_signer_certificate_verifies_digest_signed_message)
{
    v3::CertificateCache cache { *crypto };
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    ASSERT_EQ(VerificationReport::Success, service->verify(message).report);

    // signer identifier is not covered by the signature
    message.set_signer_identifier(ticket.calculate_digest(*crypto).value());
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
    v3::IssuerMemoryLookup no_issuers { *crypto };
    CryptoProviderVerifyService verifier { runtime, *crypto, positioning };
    verifier.use_issuer_lookup(&no_issuers);
    const VerifyConfirm confirm = verifier.verify(sign_message(ticket, ticket_key));
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_is_accepted_without_issuers)
{
    CryptoProviderVerifyService verifier { runtime, *crypto, positioning };
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
    v3::CertificateCache cache { *crypto };
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    ASSERT_EQ(VerificationReport::Success, service->verify(message).report);

    // issuer is not trusted anymore, e.g. revoked meanwhile
    v3::IssuerMemoryLookup no_issuers { *crypto };
    CryptoProviderVerifyService verifier { runtime, *crypto, positioning };
    verifier.use_issuer_lookup(&no_issuers);
    verifier.use_certificate_cache(&cache);
    message.set_signer_identifier(ticket.calculate_digest(*crypto).value());
    const VerifyConfirm confirm = verifier.verify(message);
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, confirm.certificate_validity.reason());
}

TEST_F(CryptoProviderVerifyServiceTest, ticket_of_falsely_signed_message_is_not_cached)
{
    v3::CertificateCache cache { *crypto };
    service->use_certificate_cache(&cache);
    v3::SecuredMessage message = sign_message(ticket, ticket_key);
    message.set_generation_time(*message.generation_time() + 1);
    ASSERT_EQ(VerificationReport::False_Signature, service->verify(message).report);
    EXPECT_EQ(nullptr, cache.lookup(ticket.calculate_digest(*crypto).value()));
}

TEST_F(CryptoProviderVerifyServiceTest, unusable_signer_key_is_invalid_certificate)
{
    CryptoProviderVerifyService verifier { runtime, *crypto, positioning };
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

TEST_F(CryptoProviderVerifyServiceTest, cam_of_unknown_station_puts_certificate_into_next_cam)
{
    v3::CertificateCache cache { *crypto };
    v3::DefaultSignHeaderPolicy policy { runtime, *crypto, positioning, cache };
    service->use_certificate_cache(&cache);
    service->use_sign_header_policy(&policy);
    // headers are prepared without signing, i.e. the own ticket's key is irrelevant
    const v3::Certificate own_ticket = v3::make_authorization_ticket(public_key(ticket_key), start);
    SignRequest cam;
    cam.its_aid = aid::CA;
    v3::SecuredMessage first_cam = v3::SecuredMessage::with_signed_data();
    // the first CAM carries the full certificate anyway
    policy.prepare_header(cam, own_ticket, first_cam);

    ASSERT_EQ(VerificationReport::Success, service->verify(sign_message(ticket, ticket_key, aid::CA)).report);

    v3::SecuredMessage next_cam = v3::SecuredMessage::with_signed_data();
    policy.prepare_header(cam, own_ticket, next_cam);
    EXPECT_TRUE(v3::contains_certificate(next_cam.signer_identifier()));
}

class CryptoProviderVerifyServiceV2Test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto) {
            GTEST_SKIP() << "no crypto provider built in";
        }
        ticket.subject_info.subject_type = v2::SubjectType::Authorization_Ticket;
        // calculate_hash serializes the signature, its r and s need 32 octets (NIST P-256)
        ticket.signature = EcdsaSignature { X_Coordinate_Only { ByteBuffer(32, 0x00) }, ByteBuffer(32, 0x00) };
        service = std::make_unique<CryptoProviderVerifyService>(runtime, *crypto, positioning);
        service->use_certificate_cache(&cache);
        service->use_certificate_validator(&validator);
        service->use_sign_header_policy(&policy);
    }

    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    StoredPositionProvider positioning;
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    v2::CertificateCache cache { runtime, crypto ? *crypto : NullCryptoProvider::instance() };
    v2::NullCertificateValidator validator;
    v2::DefaultSignHeaderPolicy policy { runtime, crypto ? *crypto : NullCryptoProvider::instance(), positioning };
    std::unique_ptr<CryptoProviderVerifyService> service;
    v2::Certificate ticket;
};

TEST_F(CryptoProviderVerifyServiceV2Test, requested_own_certificate_is_signer_of_next_cam)
{
    v2::StaticCertificateProvider own_certificates { ticket, ecdsa256::PrivateKey {} };
    SignRequest cam;
    cam.its_aid = aid::CA;
    // the first CAM carries the full certificate anyway
    policy.prepare_header(cam, own_certificates);

    v2::SecuredMessage message;
    message.payload.type = v2::PayloadType::Signed;
    message.header_fields.push_back(std::list<HashedId3> { truncate(calculate_hash(*crypto, ticket)) });
    service->verify(message);

    for (const v2::HeaderField& field : policy.prepare_header(cam, own_certificates)) {
        if (get_type(field) == v2::HeaderFieldType::Signer_Info) {
            EXPECT_EQ(v2::SignerInfoType::Certificate, get_type(boost::get<v2::SignerInfo>(field)));
            return;
        }
    }
    ADD_FAILURE() << "CAM header without signer info";
}

TEST_F(CryptoProviderVerifyServiceV2Test, unusable_ticket_key_is_invalid_certificate)
{
    // x-coordinate exceeds the curve's prime, i.e. the key is no point of the curve
    const v2::ecdsa_nistp256_with_sha256 unusable_key { Compressed_Lsb_Y_0 { ByteBuffer(32, 0xff) } };
    ticket.subject_attributes.push_back(v2::VerificationKey { unusable_key });
    v2::SecuredMessage message;
    message.payload.type = v2::PayloadType::Signed;
    message.header_fields.push_back(v2::convert_time64(runtime.now()));
    message.header_fields.push_back(v2::IntX { aid::DEN });
    message.header_fields.push_back(v2::SignerInfo { ticket });
    message.trailer_fields.push_back(
        v2::Signature { EcdsaSignature { X_Coordinate_Only { ByteBuffer(32, 0x01) }, ByteBuffer(32, 0x01) } });

    const VerifyConfirm confirm = service->verify(message);
    EXPECT_EQ(VerificationReport::Invalid_Certificate, confirm.report);
    ASSERT_FALSE(confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Missing_Public_Key, confirm.certificate_validity.reason());
}
