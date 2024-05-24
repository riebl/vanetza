#include <gtest/gtest.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/straight_verify_service.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/default_certificate_validator.hpp>
#include <vanetza/security/v2/naive_certificate_provider.hpp>
#include <vanetza/security/v2/null_certificate_validator.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/signer_info.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/static_certificate_provider.hpp>
#include <vanetza/security/v2/trust_store.hpp>
#include <vanetza/security/tests/check_payload.hpp>
#include <vanetza/security/tests/check_signature.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v2;
using vanetza::geonet::distance_u16t;
using vanetza::geonet::geo_angle_i32t;
using vanetza::units::si::meter;

void use_verify_service_component(StraightVerifyService* service, v2::CertificateCache* cache)
{
    service->use_certificate_cache(cache);
}

void use_verify_service_component(StraightVerifyService* service, v2::CertificateProvider* provider)
{
    service->use_certificate_provider(provider);
}

void use_verify_service_component(StraightVerifyService* service, v2::CertificateValidator* validator)
{
    service->use_certitifcate_validator(validator);
}

void use_verify_service_component(StraightVerifyService* service, v2::SignHeaderPolicy* policy)
{
    service->use_sign_header_policy(policy);
}

void use_verify_service_component_expansion(StraightVerifyService*)
{
    // end of recursive paramater pack expansion: no-op
}

template<typename Arg, typename... Args>
void use_verify_service_component_expansion(StraightVerifyService* service, Arg arg, Args... args)
{
    use_verify_service_component(service, arg);
    use_verify_service_component_expansion(service, std::forward<Args>(args)...);
}


class SecurityEntityTest : public ::testing::Test
{
protected:
    SecurityEntityTest() :
        runtime(Clock::at("2016-03-7 08:23")),
        crypto_backend(create_backend("default")),
        certificate_provider(new NaiveCertificateProvider(runtime)),
        cert_cache(runtime),
        certificate_validator(new DefaultCertificateValidator(*crypto_backend, cert_cache, trust_store)),
        sign_header_policy(runtime, position_provider),
        security(create_sign_service(), create_verify_service()),
        its_aid(aid::CA)
    {
        trust_store.insert(certificate_provider->root_certificate());

        PositionFix position_fix;
        position_fix.latitude = 49.014420 * units::degree;
        position_fix.longitude = 8.404417 * units::degree;
        position_fix.confidence.semi_major = 25.0 * units::si::meter;
        position_fix.confidence.semi_minor = 25.0 * units::si::meter;
        assert(position_fix.confidence);
        position_provider.position_fix(position_fix);
    }

    void SetUp() override
    {
        expected_payload[OsiLayer::Transport] = ByteBuffer {89, 27, 1, 4, 18, 85};

        for (auto cert : certificate_provider->own_chain()) {
            cert_cache.insert(cert);
        }
    }

    std::unique_ptr<SignService> create_sign_service()
    {
        return std::unique_ptr<SignService> {
            new StraightSignService(*certificate_provider, *crypto_backend, sign_header_policy)
        };
    }

    std::unique_ptr<StraightVerifyService> create_straight_verify_service()
    {
        std::unique_ptr<StraightVerifyService> service {
            new StraightVerifyService(runtime, *crypto_backend, position_provider)
        };
        service->use_certificate_cache(&cert_cache);
        service->use_certificate_provider(certificate_provider.get());
        service->use_certitifcate_validator(certificate_validator.get());
        service->use_sign_header_policy(&sign_header_policy);
        return service;
    }

    std::unique_ptr<VerifyService> create_verify_service()
    {
        return create_straight_verify_service();
    }

    template<typename... Args>
    std::unique_ptr<VerifyService> create_verify_service(Args... args)
    {
        auto service = create_straight_verify_service();
        use_verify_service_component_expansion(service.get(), std::forward<Args>(args)...);
        return service;
    }

    EncapRequest create_encap_request()
    {
        EncapRequest encap_request;
        encap_request.plaintext_payload = expected_payload;
        encap_request.its_aid = its_aid;
        return encap_request;
    }

    v2::SecuredMessage create_secured_message()
    {
        EncapConfirm confirm = security.encapsulate_packet(create_encap_request());
        return boost::get<v2::SecuredMessage>(confirm.sec_packet);
    }

    v2::SecuredMessage create_secured_message(v2::Certificate& modified_certificate)
    {
        // we need to sign with the modified certificate, otherwise validation just fails because of a wrong signature
        StaticCertificateProvider local_cert_provider(modified_certificate, certificate_provider->own_private_key());
        DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
        std::unique_ptr<SignService> local_sign_service { new StraightSignService(local_cert_provider, *crypto_backend, sign_header_policy) };
        DelegatingSecurityEntity local_security(std::move(local_sign_service), create_verify_service());

        EncapConfirm confirm = local_security.encapsulate_packet(create_encap_request());
        return boost::get<v2::SecuredMessage>(confirm.sec_packet);
    }

    ManualRuntime runtime;
    StoredPositionProvider position_provider;
    std::unique_ptr<Backend> crypto_backend;
    std::unique_ptr<NaiveCertificateProvider> certificate_provider;
    std::vector<v2::Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    std::unique_ptr<CertificateValidator> certificate_validator;
    DefaultSignHeaderPolicy sign_header_policy;
    DelegatingSecurityEntity security;
    ChunkPacket expected_payload;
    ItsAid its_aid;
};

TEST_F(SecurityEntityTest, mutual_acceptance)
{
    DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
    std::unique_ptr<SignService> sign { new StraightSignService(*certificate_provider, *crypto_backend, sign_header_policy) };
    std::unique_ptr<StraightVerifyService> verify { new StraightVerifyService(runtime, *crypto_backend, position_provider) };
    verify->use_certificate_cache(&cert_cache);
    verify->use_certificate_provider(certificate_provider.get());
    verify->use_certitifcate_validator(certificate_validator.get());
    verify->use_sign_header_policy(&sign_header_policy);
    DelegatingSecurityEntity other_security(std::move(sign), std::move(verify));
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}

#if defined(VANETZA_WITH_CRYPTOPP) && defined(VANETZA_WITH_OPENSSL)
TEST_F(SecurityEntityTest, mutual_acceptance_impl)
{
    auto cryptopp_backend = create_backend("CryptoPP");
    auto openssl_backend = create_backend("OpenSSL");
    ASSERT_TRUE(cryptopp_backend);
    ASSERT_TRUE(openssl_backend);

    DefaultSignHeaderPolicy sign_header_policy_cryptopp(runtime, position_provider);
    std::unique_ptr<StraightVerifyService> cryptopp_verify_service {
        new StraightVerifyService(runtime, *cryptopp_backend, position_provider)
    };
    cryptopp_verify_service->use_certificate_cache(&cert_cache);
    cryptopp_verify_service->use_certificate_provider(certificate_provider.get());
    cryptopp_verify_service->use_certitifcate_validator(certificate_validator.get());
    cryptopp_verify_service->use_sign_header_policy(&sign_header_policy_cryptopp);
    DelegatingSecurityEntity cryptopp_security {
        std::unique_ptr<SignService> {
            new StraightSignService(*certificate_provider, *cryptopp_backend, sign_header_policy_cryptopp) },
        std::move(cryptopp_verify_service)
    };

    DefaultSignHeaderPolicy sign_header_policy_openssl(runtime, position_provider);
    std::unique_ptr<StraightVerifyService> openssl_verify_service {
        new StraightVerifyService(runtime, *openssl_backend, position_provider)
    };
    openssl_verify_service->use_certificate_cache(&cert_cache);
    openssl_verify_service->use_certificate_provider(certificate_provider.get());
    openssl_verify_service->use_certitifcate_validator(certificate_validator.get());
    openssl_verify_service->use_sign_header_policy(&sign_header_policy_openssl);
    DelegatingSecurityEntity openssl_security {
        std::unique_ptr<SignService> {
            new StraightSignService(*certificate_provider, *openssl_backend, sign_header_policy_cryptopp) },
        std::move(openssl_verify_service)
    };

    // OpenSSL to Crypto++
    EncapConfirm encap_confirm = openssl_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = cryptopp_security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);

    // Crypto++ to OpenSSL
    encap_confirm = cryptopp_security.encapsulate_packet(create_encap_request());
    decap_confirm = openssl_security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}
#endif

TEST_F(SecurityEntityTest, captured_acceptance)
{
    const char secured_cam[] =
            "0280bc8002020118180bd751330373010056000004058caca9488f1710d7e7407b5402bc2986a87c43c9d695e91eacee9b1495060d"
            "403d64f8f9ef25e269b586042490f2b24b761f639b8bd2691a4a9e17a4392d3d020020022425210b240301889c2504010000000901"
            "1a9230c01b99ead00000771505917c6ecfe986f3a446eadd8277712a6cb8189312330cc862b5bffa7dea375ae9f3349cf2038e67f2"
            "4f4a9ab050af72c3809b654117ca6632afc8e8eb7c00000195732e7667fd05240181102050030000ec01003ce8000d411004f9cb88"
            "5ef11d36b23105057269800000000000000007d100000102001003f8303900fa5b73662e09e88d3ffffffc2230d400bed4952be91d"
            "417b198780000ce9a92a5d633a82f4df0f00001a1352554e647507c64421800033b6a4aa9cc8ea0f8c88430000686d495306e9d429"
            "5268860000cf1a92a60dd3a852a4d10c0001a2352544b36750fbf2a21000033e6a4a8966cea1f7e5442000068cd494fb9e9d455964"
            "8860000cfda929f73d3a8ab2c910c0001a3b52541d007519b12e2100003406a4a83a00ea33625c420000690d49529781d475dfc084"
            "0000cada92a52f03a8ebbf810800019735256b538751d985c21000032c6a4ad6a70ea3b30b842000065e43010000e7adf7c0ec3e51"
            "765b6f5366837cda248d22f66da7d806e740810de221c6bd389c060bd02c48a9a574f32ec5a193ed2de21ef6d86de9e7c313d364f8"
            "91398776";

    v2::SecuredMessage v2_message;
    deserialize_from_hexstring(secured_cam, v2_message);
    security::SecuredMessage message = v2_message;

    runtime.reset(Clock::at("2018-02-15 16:28:30"));

    NullCertificateValidator validator;
    validator.certificate_check_result(CertificateValidity::valid());
    std::unique_ptr<VerifyService> verify = create_verify_service(&validator);
    DelegatingSecurityEntity dummy_security(create_sign_service(), std::move(verify));

    // We only care about the message signature here to be valid, the certificate isn't validated.
    DecapConfirm decap_confirm = dummy_security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}

TEST_F(SecurityEntityTest, signed_payload_equals_plaintext_payload)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());

    // check if sec_payload equals plaintext_payload
    check(expected_payload, boost::get<v2::SecuredMessage>(confirm.sec_packet).payload.data);
}

TEST_F(SecurityEntityTest, signature_is_ecdsa)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());
    auto msg = boost::get<v2::SecuredMessage>(confirm.sec_packet);

    // check if trailer_fields contain signature
    EXPECT_EQ(1, msg.trailer_fields.size());
    auto signature = msg.trailer_field(TrailerFieldType::Signature);
    ASSERT_TRUE(!!signature);
    auto signature_type = get_type(boost::get<v2::Signature>(*signature));
    EXPECT_EQ(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, signature_type);
}

TEST_F(SecurityEntityTest, signer_info_is_encoded_first)
{
    auto message = create_secured_message();
    EXPECT_EQ(HeaderFieldType::Signer_Info, get_type(message.header_fields.front()));

    // cause inclusion of additional header field that should not change order of header fields
    sign_header_policy.request_unrecognized_certificate(HashedId8({ 0, 0, 0, 0, 0, 0, 0, 0 }));

    message = create_secured_message();
    EXPECT_EQ(HeaderFieldType::Signer_Info, get_type(message.header_fields.front()));
}

TEST_F(SecurityEntityTest, expected_header_field_size)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());
    auto msg = boost::get<v2::SecuredMessage>(confirm.sec_packet);

    // check header_field size
    EXPECT_EQ(3, msg.header_fields.size());
}

TEST_F(SecurityEntityTest, expected_payload)
{
    EncapConfirm confirm = security.encapsulate_packet(create_encap_request());
    auto msg = boost::get<v2::SecuredMessage>(confirm.sec_packet);

    // check payload
    Payload payload = msg.payload;
    EXPECT_EQ(expected_payload.size(), size(payload.data, min_osi_layer(), max_osi_layer()));
    EXPECT_EQ(PayloadType::Signed, get_type(payload));
}

TEST_F(SecurityEntityTest, verify_message)
{
    // build valid message
    security::SecuredMessage secured_message = create_secured_message();
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { secured_message });

    // check if verify was successful
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    // check if payload was not changed
    check(expected_payload, decap_confirm.plaintext_payload);
    // check certificate validity
    EXPECT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_message_modified_message_type)
{
    // build message with wrong ITS-AID
    auto v2_secured_message = create_secured_message();
    IntX* its_aid = v2_secured_message.header_field<HeaderFieldType::Its_Aid>();
    ASSERT_TRUE(its_aid);
    its_aid->set(42);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { v2_secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_name)
{
    // change the subject name
    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.subject_info.subject_name = {42};

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Name, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signer_info)
{
    // change the subject info
    v2::Certificate certificate = certificate_provider->own_certificate();
    HashedId8 faulty_hash ({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    certificate.signer_info = faulty_hash;

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_info)
{
    // change the subject info
    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.subject_info.subject_type = SubjectType::Root_CA;

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_assurance)
{
    v2::Certificate certificate = certificate_provider->own_certificate();
    for (auto& subject_attribute : certificate.subject_attributes) {
        if (SubjectAttributeType::Assurance_Level == get_type(subject_attribute)) {
            SubjectAssurance& subject_assurance = boost::get<SubjectAssurance>(subject_attribute);
            // change raw in subject assurance
            subject_assurance.raw = 0x47;
        }
    }

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_outdated_certificate)
{
    // forge certificate with outdated validity
    StartAndEndValidity outdated_validity;
    outdated_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    outdated_validity.end_validity = convert_time32(runtime.now() - std::chrono::minutes(1));

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(outdated_validity);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_premature_certificate)
{
    // forge certificate with premature validity
    StartAndEndValidity premature_validity;
    premature_validity.start_validity = convert_time32(runtime.now() + std::chrono::hours(1));
    premature_validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(5));

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(premature_validity);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_validity_restriction)
{
    v2::Certificate certificate = certificate_provider->own_certificate();
    for (auto& validity_restriction : certificate.validity_restriction) {
        ValidityRestrictionType type = get_type(validity_restriction);
        ASSERT_EQ(type, ValidityRestrictionType::Time_Start_And_End);

        // change start and end time of certificate validity
        StartAndEndValidity& start_and_end = boost::get<StartAndEndValidity>(validity_restriction);
        start_and_end.start_validity = 500;
        start_and_end.end_validity = 373;
    }

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Broken_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signature)
{
    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.signature = create_random_ecdsa_signature(0);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_signature)
{
    // hamper with signature
    auto v2_secured_message = create_secured_message();
    v2::Signature* signature = v2_secured_message.trailer_field<TrailerFieldType::Signature>();
    ASSERT_TRUE(signature);
    ASSERT_EQ(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, get_type(*signature));
    EcdsaSignature& ecdsa_signature = boost::get<EcdsaSignature>(signature->some_ecdsa);
    ecdsa_signature.s = {8, 15, 23};

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { v2_secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_payload_type)
{
    // change the payload type (should break signature)
    auto v2_secured_message = create_secured_message();
    v2_secured_message.payload.type = PayloadType::Unsecured;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { v2_secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::Unsigned_Message, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_modified_payload)
{
    // modify payload buffer
    auto v2_secured_message = create_secured_message();
    v2_secured_message.payload.data = CohesivePacket({42, 42, 42}, OsiLayer::Session);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { v2_secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::False_Signature, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_generation_time_before_current_time)
{
    // prepare decap request
    security::SecuredMessage secured_message = create_secured_message();

    // change the time, so the generation time of SecuredMessage is before current time
    runtime.trigger(std::chrono::hours(12));

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::Invalid_Timestamp, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_generation_time_after_current_time)
{
    // change the time, so the generation time of SecuredMessage is after current time
    runtime.trigger(std::chrono::hours(12));

    // prepare decap request
    security::SecuredMessage secured_message = create_secured_message();

    // change the time, so the current time is before generation time of SecuredMessage
    runtime.reset(runtime.now() - std::chrono::hours(12));

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { secured_message });
    // check if verify was successful
    EXPECT_EQ(DecapReport::Invalid_Timestamp, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_without_signer_info)
{
    auto v2_secured_message = create_secured_message();
    // iterate through all header_fields
    auto& header_fields = v2_secured_message.header_fields;
    for (auto field = header_fields.begin(); field != header_fields.end(); ++field) {
        // modify certificate
        if (HeaderFieldType::Signer_Info == get_type(*field)) {
            header_fields.erase(field);
            break;
        }
    }

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { v2_secured_message});
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
    auto aid_header = secured_message.header_field<HeaderFieldType::Its_Aid>();
    ASSERT_EQ(*aid_header, aid::CA);
}

// See TS 103 096-2 v1.3.1, section 5.2.4.2
TEST_F(SecurityEntityTest, verify_message_header_fields_cam)
{
    auto secured_message = create_secured_message();
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Signer_Info>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Its_Aid>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Generation_Time>());
    EXPECT_EQ(nullptr, secured_message.header_field<HeaderFieldType::Generation_Time_Confidence>());
    EXPECT_EQ(nullptr, secured_message.header_field<HeaderFieldType::Expiration>());
    EXPECT_EQ(nullptr, secured_message.header_field<HeaderFieldType::Encryption_Parameters>());
    EXPECT_EQ(nullptr, secured_message.header_field<HeaderFieldType::Recipient_Info>());

    EXPECT_EQ(HeaderFieldType::Signer_Info, get_type(secured_message.header_fields.front()));

    using enum_int = std::underlying_type<HeaderFieldType>::type;
    HeaderFieldType previous_field = HeaderFieldType::Signer_Info;
    for (auto& field : secured_message.header_fields) {
        if (get_type(field) == HeaderFieldType::Signer_Info) {
            continue;
        }

        if (previous_field == HeaderFieldType::Signer_Info) {
            previous_field = get_type(field);
            continue;
        }

        // check ascending order
        EXPECT_GT(static_cast<enum_int>(get_type(field)), static_cast<enum_int>(previous_field));
        previous_field = get_type(field);
    }
}

// See TS 103 096-2 v1.3.1, section 5.2.5.2
TEST_F(SecurityEntityTest, verify_message_header_fields_denm)
{
    its_aid = aid::DEN;

    auto secured_message = create_secured_message();
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Signer_Info>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Its_Aid>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Generation_Time>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Generation_Location>());
    EXPECT_EQ(nullptr, secured_message.header_field<HeaderFieldType::Generation_Time_Confidence>());

    EXPECT_EQ(HeaderFieldType::Signer_Info, get_type(secured_message.header_fields.front()));

    using enum_int = std::underlying_type<HeaderFieldType>::type;
    HeaderFieldType previous_field = HeaderFieldType::Signer_Info;
    for (auto& field : secured_message.header_fields) {
        if (get_type(field) == HeaderFieldType::Signer_Info) {
            continue;
        }

        if (previous_field == HeaderFieldType::Signer_Info) {
            previous_field = get_type(field);
            continue;
        }

        // check ascending order
        EXPECT_GT(static_cast<enum_int>(get_type(field)), static_cast<enum_int>(previous_field));
        previous_field = get_type(field);
    }
}

// See TS 103 096-2 v1.3.1, section 5.2.6.2
TEST_F(SecurityEntityTest, verify_message_header_fields_other)
{
    its_aid = aid::GN_MGMT;

    auto secured_message = create_secured_message();
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Signer_Info>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Generation_Time>());
    EXPECT_NE(nullptr, secured_message.header_field<HeaderFieldType::Generation_Location>());

    EXPECT_EQ(HeaderFieldType::Signer_Info, get_type(secured_message.header_fields.front()));

    using enum_int = std::underlying_type<HeaderFieldType>::type;
    HeaderFieldType previous_field = HeaderFieldType::Signer_Info;
    for (auto& field : secured_message.header_fields) {
        if (get_type(field) == HeaderFieldType::Signer_Info) {
            continue;
        }

        if (previous_field == HeaderFieldType::Signer_Info) {
            previous_field = get_type(field);
            continue;
        }

        // check ascending order
        EXPECT_GT(static_cast<enum_int>(get_type(field)), static_cast<enum_int>(previous_field));
        previous_field = get_type(field);
    }
}

// See TS 103 096-2 v1.3.1, section 5.2.4.3 + 5.2.4.5 + 5.2.4.6 + 5.2.4.7
TEST_F(SecurityEntityTest, verify_message_signer_info_cam)
{
    auto signer_info = [](v2::SecuredMessage& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        return *signer_info;
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
    sign_header_policy.request_certificate();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }

    // certificate chain has been requested by another party, send certificate chain
    sign_header_policy.request_certificate_chain();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Chain);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }

    runtime.trigger(std::chrono::seconds(1));

    // one second has passed, send certificate
    sign_header_policy.request_certificate();
    secured_message = create_secured_message();
    ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);

    // next messages must be signed with certificate digest, until one second is over or certificate has been requested
    for (int i = 0; i < 5; i++) {
        secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate_Digest_With_SHA256);
    }
}

// See TS 103 096-2 v1.3.1, section 5.2.5.3
TEST_F(SecurityEntityTest, verify_message_signer_info_denm)
{
    auto signer_info = [](v2::SecuredMessage& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        return *signer_info;
    };

    its_aid = aid::DEN;

    // all message must be signed with certificate
    for (int i = 0; i < 3; i++) {
        auto secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);
    }
}

// See TS 103 096-2 v1.3.1, section 5.2.6.3
TEST_F(SecurityEntityTest, verify_message_signer_info_other)
{
    auto signer_info = [](v2::SecuredMessage& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        return *signer_info;
    };

    its_aid = aid::GN_MGMT; // something other than CA or DEN

    // all message must be signed with certificate
    for (int i = 0; i < 3; i++) {
        auto secured_message = create_secured_message();
        ASSERT_EQ(get_type(signer_info(secured_message)), SignerInfoType::Certificate);
    }
}

TEST_F(SecurityEntityTest, verify_message_without_position_and_with_restriction)
{
    // certificate with region restriction
    v2::CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = v2::TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    PositionFix unknown;
    ASSERT_FALSE(unknown.confidence);
    position_provider.position_fix(unknown);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Region, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_position_and_without_restriction)
{
    PositionFix unknown;
    ASSERT_FALSE(unknown.confidence);
    position_provider.position_fix(unknown);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message();
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    ASSERT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_message_with_insufficient_aid)
{
    its_aid = 42; // some random value not present in the certificate

    // verify message
    security::SecuredMessage sec_msg = create_secured_message();
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Insufficient_ITS_AID, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_non_cam_generation_location_ok)
{
    its_aid = aid::GN_MGMT;

    // certificate with region restriction
    v2::CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = v2::TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    ASSERT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_non_cam_generation_location_fail)
{
    its_aid = aid::GN_MGMT;

    // certificate with region restriction
    v2::CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = v2::TwoDLocation {
        geo_angle_i32t::from_value(10139190),
        geo_angle_i32t::from_value(84044460)
    };

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    security::SecuredMessage sec_msg = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { sec_msg });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Region, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_signature)
{
    auto v2_message = create_secured_message();
    v2_message.trailer_fields.clear();
    security::SecuredMessage message = v2_message;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Unsigned_Message, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_with_signer_info_hash)
{
    auto message_with_cert = create_secured_message();
    auto signer_info_cert = message_with_cert.header_field<HeaderFieldType::Signer_Info>();
    ASSERT_EQ(get_type(*signer_info_cert), SignerInfoType::Certificate);
    auto message_with_digest = create_secured_message();
    auto signer_info_digest = message_with_digest.header_field<HeaderFieldType::Signer_Info>();
    ASSERT_EQ(get_type(*signer_info_digest), SignerInfoType::Certificate_Digest_With_SHA256);
    security::SecuredMessage message = message_with_digest;

    // verify message - hash unknown
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Signer_Certificate_Not_Found, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 1);

    cert_cache.insert(certificate_provider->own_certificate());

    // verify message - certificate now known
    decap_confirm = security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 2);
}

TEST_F(SecurityEntityTest, verify_message_with_signer_info_chain)
{
    sign_header_policy.request_certificate_chain();

    auto v2_message = create_secured_message();
    auto signer_info = v2_message.header_field<HeaderFieldType::Signer_Info>();
    ASSERT_EQ(get_type(*signer_info), SignerInfoType::Certificate_Chain);

    // verify message - hash unknown
    security::SecuredMessage message = v2_message;
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 2);
}

TEST_F(SecurityEntityTest, verify_message_without_time_and_dummy_certificate_verify)
{
    DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
    std::unique_ptr<SignService> sign { new StraightSignService(*certificate_provider, *crypto_backend, sign_header_policy) };
    NullCertificateValidator validator;
    validator.certificate_check_result(CertificateValidity::valid());
    std::unique_ptr<VerifyService> verify = create_verify_service(&validator, &sign_header_policy);
    DelegatingSecurityEntity other_security(std::move(sign), std::move(verify));

    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.remove_restriction(ValidityRestrictionType::Time_Start_And_End);
    certificate_provider->sign_authorization_ticket(certificate);

    security::SecuredMessage message = create_secured_message(certificate);
    DecapConfirm decap_confirm = other_security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_public_key_in_certificate)
{
    v2::Certificate certificate = certificate_provider->own_certificate();
    certificate.remove_attribute(SubjectAttributeType::Verification_Key);
    certificate_provider->sign_authorization_ticket(certificate);

    security::SecuredMessage message = create_secured_message(certificate);
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { message });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Missing_Public_Key, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_certificate_requests)
{
    auto signer_info = [](v2::SecuredMessage& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        return *signer_info;
    };
    auto msg = [](EncapConfirm& confirm) -> v2::SecuredMessage& {
        return boost::get<v2::SecuredMessage>(confirm.sec_packet);
    };

    NaiveCertificateProvider other_provider(runtime);
    DefaultSignHeaderPolicy other_policy(runtime, position_provider);
    std::unique_ptr<SignService> sign { new StraightSignService(other_provider, *crypto_backend, other_policy) };
    std::unique_ptr<VerifyService> verify = create_verify_service(&other_provider, &other_policy);
    DelegatingSecurityEntity other_security(std::move(sign), std::move(verify));


    // Security entity doesn't request certificate of other
    EncapConfirm encap_confirm = security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(nullptr, msg(encap_confirm).header_field<HeaderFieldType::Request_Unrecognized_Certificate>());

    // Create message with hash from other, thus two times
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(msg(encap_confirm))), SignerInfoType::Certificate_Digest_With_SHA256);

    // Unknown certificate hash incoming from other
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Signer_Certificate_Not_Found, decap_confirm.report);

    // Security entity does request certificate from other
    encap_confirm = security.encapsulate_packet(create_encap_request());
    ASSERT_NE(nullptr, msg(encap_confirm).header_field<HeaderFieldType::Request_Unrecognized_Certificate>());

    // Other hasn't received certificate request, yet, so sends with hash
    EncapConfirm other_encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(msg(encap_confirm))), SignerInfoType::Certificate_Digest_With_SHA256);

    // Other receives certificate request and sends certificate with next message
    decap_confirm = other_security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(msg(encap_confirm))), SignerInfoType::Certificate);
}

TEST_F(SecurityEntityTest, verify_denm_without_generation_location)
{
    NaiveCertificateProvider other_provider(runtime);

    class NoLocationHeaderPolicy : public DefaultSignHeaderPolicy
    {
    public:
        NoLocationHeaderPolicy(const Runtime& rt, PositionProvider& positioning) :
            DefaultSignHeaderPolicy(rt, positioning), m_runtime(rt) {}

        std::list<HeaderField> prepare_header(const SignRequest& request, v2::CertificateProvider& certificate_provider) override
        {
            std::list<HeaderField> header_fields;

            header_fields.push_back(SignerInfo { certificate_provider.own_certificate() });
            header_fields.push_back(convert_time64(m_runtime.now()));
            header_fields.push_back(IntX(request.its_aid));

            return header_fields;
        }

    private:
        const Runtime& m_runtime;
    } other_policy(runtime, position_provider);

    std::unique_ptr<SignService> sign { new StraightSignService(other_provider, *crypto_backend, other_policy) };
    std::unique_ptr<VerifyService> verify = create_verify_service(&other_provider, &other_policy);
    DelegatingSecurityEntity other_security(std::move(sign), std::move(verify));

    its_aid = aid::DEN;
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Region, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_its_aid)
{
    NaiveCertificateProvider other_provider(runtime);

    class NoneHeaderPolicy : public DefaultSignHeaderPolicy
    {
    public:
        using DefaultSignHeaderPolicy::DefaultSignHeaderPolicy;

        std::list<HeaderField> prepare_header(const SignRequest& request, v2::CertificateProvider& certificate_provider) override
        {
            std::list<HeaderField> header_fields;
            return header_fields;
        }
    } other_policy(runtime, position_provider);

    std::unique_ptr<SignService> sign { new StraightSignService(other_provider, *crypto_backend, other_policy) };
    std::unique_ptr<VerifyService> verify = create_verify_service(&other_provider, &other_policy);
    DelegatingSecurityEntity other_security(std::move(sign), std::move(verify));

    its_aid = aid::DEN;
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    auto msg = boost::get<v2::SecuredMessage>(encap_confirm.sec_packet);
    ASSERT_EQ(nullptr, msg.header_field<HeaderFieldType::Its_Aid>());

    DecapConfirm decap_confirm = security.decapsulate_packet(SecuredMessageView { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Incompatible_Protocol, decap_confirm.report);
}

// TODO add tests for Unsupported_Signer_Identifier_Type, Incompatible_Protocol
