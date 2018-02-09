#include <gtest/gtest.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/static_certificate_provider.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/tests/check_payload.hpp>
#include <vanetza/security/tests/check_signature.hpp>

using namespace vanetza;
using namespace vanetza::security;

class SecurityEntityTest : public ::testing::Test
{
protected:
    SecurityEntityTest() :
        runtime(Clock::at("2016-03-7 08:23")),
        crypto_backend(create_backend("default")),
        certificate_provider(new NaiveCertificateProvider(runtime.now())),
        cert_cache(runtime),
        certificate_validator(new DefaultCertificateValidator(*crypto_backend, runtime.now(), position_provider, trust_store, cert_cache)),
        sign_header_policy(runtime.now()),
        sign_service(straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy)),
        verify_service(straight_verify_service(runtime, *certificate_provider, *certificate_validator, *crypto_backend, cert_cache, sign_header_policy)),
        security(sign_service, verify_service)
    {
        trust_store.insert(certificate_provider->root_certificate());
    }

    void SetUp() override
    {
        expected_payload[OsiLayer::Transport] = ByteBuffer {89, 27, 1, 4, 18, 85};

        for (auto cert : certificate_provider->own_chain()) {
            cert_cache.insert(cert);
        }
    }

    EncapRequest create_encap_request()
    {
        EncapRequest encap_request;
        encap_request.plaintext_payload = expected_payload;
        encap_request.its_aid = aid::CA;
        return encap_request;
    }

    SecuredMessage create_secured_message()
    {
        EncapConfirm confirm = security.encapsulate_packet(create_encap_request());
        return confirm.sec_packet;
    }

    SecuredMessage create_secured_message(Certificate& modified_certificate)
    {
        // we need to sign with the modified certificate, otherwise validation just fails because of a wrong signature
        StaticCertificateProvider local_cert_provider(modified_certificate, certificate_provider.get()->own_private_key());
        SignHeaderPolicy sign_header_policy(runtime.now());
        SignService local_sign_service(straight_sign_service(local_cert_provider, *crypto_backend, sign_header_policy));
        SecurityEntity local_security(local_sign_service, verify_service);

        EncapConfirm confirm = local_security.encapsulate_packet(create_encap_request());
        return confirm.sec_packet;
    }

    Runtime runtime;
    StoredPositionProvider position_provider;
    std::unique_ptr<Backend> crypto_backend;
    std::unique_ptr<NaiveCertificateProvider> certificate_provider;
    std::vector<Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    std::unique_ptr<CertificateValidator> certificate_validator;
    SignHeaderPolicy sign_header_policy;
    SignService sign_service;
    VerifyService verify_service;
    SecurityEntity security;
    ChunkPacket expected_payload;
};

TEST_F(SecurityEntityTest, mutual_acceptance)
{
    SignHeaderPolicy sign_header_policy(runtime.now());
    SignService sign = straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy);
    VerifyService verify = straight_verify_service(runtime, *certificate_provider, *certificate_validator, *crypto_backend, cert_cache, sign_header_policy);
    SecurityEntity other_security(sign, verify);
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}

#if defined(VANETZA_WITH_CRYPTOPP) && defined(VANETZA_WITH_OPENSSL)
TEST_F(SecurityEntityTest, mutual_acceptance_impl)
{
    auto cryptopp_backend = create_backend("CryptoPP");
    auto openssl_backend = create_backend("OpenSSL");
    ASSERT_TRUE(cryptopp_backend);
    ASSERT_TRUE(openssl_backend);
    security::SignHeaderPolicy sign_header_policy_openssl(runtime.now());
    security::SignHeaderPolicy sign_header_policy_cryptopp(runtime.now());
    SecurityEntity cryptopp_security {
            straight_sign_service(*certificate_provider, *cryptopp_backend, sign_header_policy_openssl),
            straight_verify_service(runtime, *certificate_provider, *certificate_validator, *cryptopp_backend, cert_cache, sign_header_policy_openssl) };
    SecurityEntity openssl_security {
            straight_sign_service(*certificate_provider, *openssl_backend, sign_header_policy_cryptopp),
            straight_verify_service(runtime, *certificate_provider, *certificate_validator, *openssl_backend, cert_cache, sign_header_policy_cryptopp) };

    // OpenSSL to Crypto++
    EncapConfirm encap_confirm = openssl_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = cryptopp_security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);

    // Crypto++ to OpenSSL
    encap_confirm = cryptopp_security.encapsulate_packet(create_encap_request());
    decap_confirm = openssl_security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}
#endif

TEST_F(SecurityEntityTest, signed_payload_equals_plaintext_payload)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());

    // check if sec_payload equals plaintext_payload
    check(expected_payload, confirm.sec_packet.payload.data);
}

TEST_F(SecurityEntityTest, signature_is_ecdsa)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());

    // check if trailer_fields contain signature
    EXPECT_EQ(1, confirm.sec_packet.trailer_fields.size());
    auto signature = confirm.sec_packet.trailer_field(TrailerFieldType::Signature);
    ASSERT_TRUE(!!signature);
    auto signature_type = get_type(boost::get<Signature>(*signature));
    EXPECT_EQ(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, signature_type);
}

TEST_F(SecurityEntityTest, expected_header_field_size)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());

    // check header_field size
    EXPECT_EQ(3, confirm.sec_packet.header_fields.size());
}

TEST_F(SecurityEntityTest, expected_payload)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());

    // check payload
    Payload payload = confirm.sec_packet.payload;
    EXPECT_EQ(expected_payload.size(), size(payload.data, min_osi_layer(), max_osi_layer()));
    EXPECT_EQ(PayloadType::Signed, get_type(payload));
}

TEST_F(SecurityEntityTest, verify_message)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));

    // check if verify was successful
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    // check if payload was not changed
    check(expected_payload, decap_confirm.plaintext_payload);
    // check certificate validity
    EXPECT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_message_modified_message_type)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    IntX* its_aid = secured_message.header_field<HeaderFieldType::Its_Aid>();
    ASSERT_TRUE(its_aid);
    its_aid->set(42);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_name)
{
    // change the subject name
    Certificate certificate = certificate_provider.get()->own_certificate();
    certificate.subject_info.subject_name = {42};

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::INVALID_NAME, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signer_info)
{
    // change the subject info
    Certificate certificate = certificate_provider.get()->own_certificate();
    HashedId8 faulty_hash {{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }};
    certificate.signer_info = faulty_hash;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::UNKNOWN_SIGNER, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_info)
{
    // change the subject info
    Certificate certificate = certificate_provider.get()->own_certificate();
    certificate.subject_info.subject_type = SubjectType::Root_Ca;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::INVALID_SIGNER, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_assurance)
{
    Certificate certificate = certificate_provider.get()->own_certificate();
    for (auto& subject_attribute : certificate.subject_attributes) {
        if (SubjectAttributeType::Assurance_Level == get_type(subject_attribute)) {
            SubjectAssurance& subject_assurance = boost::get<SubjectAssurance>(subject_attribute);
            // change raw in subject assurance
            subject_assurance.raw = 0x47;
        }
    }

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::UNKNOWN_SIGNER, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_outdated_certificate)
{
    // forge certificate with outdated validity
    StartAndEndValidity outdated_validity;
    outdated_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    outdated_validity.end_validity = convert_time32(runtime.now() - std::chrono::minutes(1));

    Certificate certificate = certificate_provider.get()->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(outdated_validity);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_TIME_PERIOD, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_premature_certificate)
{
    // forge certificate with premature validity
    StartAndEndValidity premature_validity;
    premature_validity.start_validity = convert_time32(runtime.now() + std::chrono::hours(1));
    premature_validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(25));

    Certificate certificate = certificate_provider.get()->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(premature_validity);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_TIME_PERIOD, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_validity_restriction)
{
    Certificate certificate = certificate_provider.get()->own_certificate();
    for (auto& validity_restriction : certificate.validity_restriction) {
        ValidityRestrictionType type = get_type(validity_restriction);
        ASSERT_EQ(type, ValidityRestrictionType::Time_Start_And_End);

        // change start and end time of certificate validity
        StartAndEndValidity& start_and_end = boost::get<StartAndEndValidity>(validity_restriction);
        start_and_end.start_validity = 500;
        start_and_end.end_validity = 373;
    }

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signature)
{
    Certificate certificate = certificate_provider.get()->own_certificate();
    certificate.signature = create_random_ecdsa_signature(0);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::UNKNOWN_SIGNER, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_signature)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    Signature* signature = secured_message.trailer_field<TrailerFieldType::Signature>();
    ASSERT_TRUE(signature);
    ASSERT_EQ(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, get_type(*signature));
    EcdsaSignature& ecdsa_signature = boost::get<EcdsaSignature>(*signature);
    ecdsa_signature.s = {8, 15, 23};

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_payload_type)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // change the payload.type
    secured_message.payload.type = PayloadType::Unsecured;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::Unsigned_Message, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_payload)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // modify payload buffer
    secured_message.payload.data = CohesivePacket({42, 42, 42}, OsiLayer::Session);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_generation_time_before_current_time)
{
    // change the time, so the generation time of SecuredMessage is before current time
    runtime.trigger(std::chrono::hours(12));

    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // change the time, so the current time is before generation time of SecuredMessage
    runtime.reset(runtime.now() - std::chrono::hours(12));

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::Invalid_Timestamp, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_without_signer_info)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // iterate through all header_fields
    auto& header_fields = secured_message.header_fields;
    for (auto field = header_fields.begin(); field != header_fields.end(); ++field) {
        // modify certificate
        if (HeaderFieldType::Signer_Info == get_type(*field)) {
            header_fields.erase(field);
            break;
        }
    }

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::Signer_Certificate_Not_Found, decap_confirm.report);
}

// See TS 103 096-2 v1.3.1, section 5.2.1
TEST_F(SecurityEntityTest, verify_message_protocol_version)
{
    auto secured_message = create_secured_message();
    ASSERT_EQ(secured_message.protocol_version(), 2);
}

// See TS 103 096-2 v1.3.1, section 5.2.4.1
TEST_F(SecurityEntityTest, verify_message_its_aid)
{
    auto secured_message = create_secured_message();
    auto aid_header = secured_message.header_field(HeaderFieldType::Its_Aid);
    ASSERT_EQ(boost::get<IntX>(*aid_header), aid::CA);
}

// See TS 103 096-2 v1.3.1, section 5.2.4.3 + 5.2.4.5 + 5.2.4.6 + 5.2.4.7
TEST_F(SecurityEntityTest, verify_message_signer_info)
{
    auto signer_info = [this](SecuredMessageV2& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field(HeaderFieldType::Signer_Info);
        return boost::get<SignerInfo>(*signer_info);
    };

    // first message must be signed with certificate
    auto secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);

        // See TS 103 096-2 v1.3.1, section 5.2.2
        ASSERT_EQ(
            boost::get<HashedId8>(signer_info(secured_message)),
            calculate_hash(certificate_provider->own_certificate())
        );
    }

    // certificate has been requested by another party, send certificate
    sign_header_policy.report_requested_certificate();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }

    // certificate chain has been requested by another party, send certificate chain
    sign_header_policy.report_requested_certificate_chain();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Chain);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }

    runtime.trigger(std::chrono::seconds(1));

    // one second has passed, send certificate
    sign_header_policy.report_requested_certificate();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }
}

// TODO add tests for Unsupported_Signer_Identifier_Type, Incompatible_Protocol
