#include <gtest/gtest.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/null_certificate_validator.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/sign_header_policy.hpp>
#include <vanetza/security/signer_info.hpp>
#include <vanetza/security/static_certificate_provider.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/security/tests/check_payload.hpp>
#include <vanetza/security/tests/check_signature.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

using namespace vanetza;
using namespace vanetza::security;
using vanetza::geonet::distance_u16t;
using vanetza::geonet::geo_angle_i32t;
using vanetza::units::si::meter;

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
        sign_service(straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy)),
        verify_service(straight_verify_service(runtime, *certificate_provider, *certificate_validator, *crypto_backend, cert_cache, sign_header_policy, position_provider)),
        security(sign_service, verify_service),
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

    EncapRequest create_encap_request()
    {
        EncapRequest encap_request;
        encap_request.plaintext_payload = expected_payload;
        encap_request.its_aid = its_aid;
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
        StaticCertificateProvider local_cert_provider(modified_certificate, certificate_provider->own_private_key());
        DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
        SignService local_sign_service(straight_sign_service(local_cert_provider, *crypto_backend, sign_header_policy));
        DelegatingSecurityEntity local_security(local_sign_service, verify_service);

        EncapConfirm confirm = local_security.encapsulate_packet(create_encap_request());
        return confirm.sec_packet;
    }

    ManualRuntime runtime;
    StoredPositionProvider position_provider;
    std::unique_ptr<Backend> crypto_backend;
    std::unique_ptr<NaiveCertificateProvider> certificate_provider;
    std::vector<Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    std::unique_ptr<CertificateValidator> certificate_validator;
    DefaultSignHeaderPolicy sign_header_policy;
    SignService sign_service;
    VerifyService verify_service;
    DelegatingSecurityEntity security;
    ChunkPacket expected_payload;
    ItsAid its_aid;
};

TEST_F(SecurityEntityTest, mutual_acceptance)
{
    DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
    SignService sign = straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy);
    VerifyService verify = straight_verify_service(runtime, *certificate_provider, *certificate_validator, *crypto_backend, cert_cache, sign_header_policy, position_provider);
    DelegatingSecurityEntity other_security(sign, verify);
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
    DefaultSignHeaderPolicy sign_header_policy_openssl(runtime, position_provider);
    DefaultSignHeaderPolicy sign_header_policy_cryptopp(runtime, position_provider);
    DelegatingSecurityEntity cryptopp_security {
            straight_sign_service(*certificate_provider, *cryptopp_backend, sign_header_policy_openssl),
            straight_verify_service(runtime, *certificate_provider, *certificate_validator, *cryptopp_backend, cert_cache, sign_header_policy_openssl, position_provider) };
    DelegatingSecurityEntity openssl_security {
            straight_sign_service(*certificate_provider, *openssl_backend, sign_header_policy_cryptopp),
            straight_verify_service(runtime, *certificate_provider, *certificate_validator, *openssl_backend, cert_cache, sign_header_policy_cryptopp, position_provider) };

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

    SecuredMessage message;
    deserialize_from_hexstring(secured_cam, message);

    runtime.reset(Clock::at("2018-02-15 16:28:30"));

    NullCertificateValidator validator;
    validator.certificate_check_result(CertificateValidity::valid());
    VerifyService verify = straight_verify_service(runtime, *certificate_provider, validator, *crypto_backend, cert_cache, sign_header_policy, position_provider);
    DelegatingSecurityEntity dummy_security(sign_service, verify);

    // We only care about the message signature here to be valid, the certificate isn't validated.
    DecapConfirm decap_confirm = dummy_security.decapsulate_packet(DecapRequest { message });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
}

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
    Certificate certificate = certificate_provider->own_certificate();
    certificate.subject_info.subject_name = {42};

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Name, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signer_info)
{
    // change the subject info
    Certificate certificate = certificate_provider->own_certificate();
    HashedId8 faulty_hash ({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
    certificate.signer_info = faulty_hash;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_info)
{
    // change the subject info
    Certificate certificate = certificate_provider->own_certificate();
    certificate.subject_info.subject_type = SubjectType::Root_CA;

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_subject_assurance)
{
    Certificate certificate = certificate_provider->own_certificate();
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
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_outdated_certificate)
{
    // forge certificate with outdated validity
    StartAndEndValidity outdated_validity;
    outdated_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    outdated_validity.end_validity = convert_time32(runtime.now() - std::chrono::minutes(1));

    Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(outdated_validity);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
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

    Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.clear();
    certificate.validity_restriction.push_back(premature_validity);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_validity_restriction)
{
    Certificate certificate = certificate_provider->own_certificate();
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
    EXPECT_EQ(CertificateInvalidReason::Broken_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_certificate_signature)
{
    Certificate certificate = certificate_provider->own_certificate();
    certificate.signature = create_random_ecdsa_signature(0);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Unknown_Signer, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_modified_signature)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    Signature* signature = secured_message.trailer_field<TrailerFieldType::Signature>();
    ASSERT_TRUE(signature);
    ASSERT_EQ(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, get_type(*signature));
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

TEST_F(SecurityEntityTest, verify_message_generation_time_before_current_time)
{
    // prepare decap request
    auto secured_message = create_secured_message();
    DecapRequest decap_request(secured_message);

    // change the time, so the generation time of SecuredMessage is before current time
    runtime.trigger(std::chrono::hours(12));

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(std::move(decap_request));
    // check if verify was successful
    EXPECT_EQ(DecapReport::Invalid_Timestamp, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_generation_time_after_current_time)
{
    // change the time, so the generation time of SecuredMessage is after current time
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
    auto signer_info = [](SecuredMessageV2& secured_message) -> SignerInfo {
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
    auto signer_info = [](SecuredMessageV2& secured_message) -> SignerInfo {
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
    auto signer_info = [](SecuredMessageV2& secured_message) -> SignerInfo {
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
    CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    PositionFix unknown;
    ASSERT_FALSE(unknown.confidence);
    position_provider.position_fix(unknown);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
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
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message() });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    ASSERT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_message_with_insufficient_aid)
{
    its_aid = 42; // some random value not present in the certificate

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message() });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Insufficient_ITS_AID, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_non_cam_generation_location_ok)
{
    its_aid = aid::GN_MGMT;

    // certificate with region restriction
    CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = TwoDLocation {
        geo_angle_i32t::from_value(490139190),
        geo_angle_i32t::from_value(84044460)
    };

    Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    ASSERT_TRUE(decap_confirm.certificate_validity);
}

TEST_F(SecurityEntityTest, verify_non_cam_generation_location_fail)
{
    its_aid = aid::GN_MGMT;

    // certificate with region restriction
    CircularRegion circle;
    circle.radius = static_cast<distance_u16t>(400 * meter);
    circle.center = TwoDLocation {
        geo_angle_i32t::from_value(10139190),
        geo_angle_i32t::from_value(84044460)
    };

    Certificate certificate = certificate_provider->own_certificate();
    certificate.validity_restriction.push_back(circle);
    certificate_provider->sign_authorization_ticket(certificate);

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { create_secured_message(certificate) });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Region, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_signature)
{
    auto message = create_secured_message();
    message.trailer_fields.clear();

    // verify message
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { message });
    EXPECT_EQ(DecapReport::Unsigned_Message, decap_confirm.report);
}

TEST_F(SecurityEntityTest, verify_message_with_signer_info_hash)
{
    auto message_a = create_secured_message();
    auto message_b = create_secured_message();

    auto signer_info = message_b.header_field<HeaderFieldType::Signer_Info>();
    ASSERT_EQ(get_type(*signer_info), SignerInfoType::Certificate_Digest_With_SHA256);

    // verify message - hash unknown
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { message_b });
    EXPECT_EQ(DecapReport::Signer_Certificate_Not_Found, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 1);

    cert_cache.insert(certificate_provider->own_certificate());

    // verify message - certificate now known
    decap_confirm = security.decapsulate_packet(DecapRequest { message_b });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 2);
}

TEST_F(SecurityEntityTest, verify_message_with_signer_info_chain)
{
    sign_header_policy.request_certificate_chain();

    auto message = create_secured_message();

    auto signer_info = message.header_field<HeaderFieldType::Signer_Info>();
    ASSERT_EQ(get_type(*signer_info), SignerInfoType::Certificate_Chain);

    // verify message - hash unknown
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { message });
    EXPECT_EQ(DecapReport::Success, decap_confirm.report);
    EXPECT_EQ(cert_cache.size(), 2);
}

TEST_F(SecurityEntityTest, verify_message_without_time_and_dummy_certificate_verify)
{
    DefaultSignHeaderPolicy sign_header_policy(runtime, position_provider);
    SignService sign = straight_sign_service(*certificate_provider, *crypto_backend, sign_header_policy);
    NullCertificateValidator validator;
    validator.certificate_check_result(CertificateValidity::valid());
    VerifyService verify = straight_verify_service(runtime, *certificate_provider, validator, *crypto_backend, cert_cache, sign_header_policy, position_provider);
    DelegatingSecurityEntity other_security(sign, verify);

    Certificate certificate = certificate_provider->own_certificate();
    certificate.remove_restriction(ValidityRestrictionType::Time_Start_And_End);
    certificate_provider->sign_authorization_ticket(certificate);

    auto message = create_secured_message(certificate);

    DecapConfirm decap_confirm = other_security.decapsulate_packet(DecapRequest { message });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Off_Time_Period, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_without_public_key_in_certificate)
{
    Certificate certificate = certificate_provider->own_certificate();
    certificate.remove_attribute(SubjectAttributeType::Verification_Key);
    certificate_provider->sign_authorization_ticket(certificate);

    auto message = create_secured_message(certificate);

    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { message });
    EXPECT_EQ(DecapReport::Invalid_Certificate, decap_confirm.report);
    ASSERT_FALSE(decap_confirm.certificate_validity);
    EXPECT_EQ(CertificateInvalidReason::Missing_Public_Key, decap_confirm.certificate_validity.reason());
}

TEST_F(SecurityEntityTest, verify_message_certificate_requests)
{
    auto signer_info = [](SecuredMessageV2& secured_message) -> SignerInfo {
        auto signer_info = secured_message.header_field<HeaderFieldType::Signer_Info>();
        return *signer_info;
    };

    NaiveCertificateProvider other_provider(runtime);
    DefaultSignHeaderPolicy other_policy(runtime, position_provider);
    SignService sign = straight_sign_service(other_provider, *crypto_backend, other_policy);
    VerifyService verify = straight_verify_service(runtime, other_provider, *certificate_validator, *crypto_backend, cert_cache, other_policy, position_provider);
    DelegatingSecurityEntity other_security(sign, verify);

    // Security entity doesn't request certificate of other
    EncapConfirm encap_confirm = security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(nullptr, encap_confirm.sec_packet.header_field<HeaderFieldType::Request_Unrecognized_Certificate>());

    // Create message with hash from other, thus two times
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(encap_confirm.sec_packet)), SignerInfoType::Certificate_Digest_With_SHA256);

    // Unknown certificate hash incoming from other
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Signer_Certificate_Not_Found, decap_confirm.report);

    // Security entity does request certificate from other
    encap_confirm = security.encapsulate_packet(create_encap_request());
    ASSERT_NE(nullptr, encap_confirm.sec_packet.header_field<HeaderFieldType::Request_Unrecognized_Certificate>());

    // Other hasn't received certificate request, yet, so sends with hash
    EncapConfirm other_encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(other_encap_confirm.sec_packet)), SignerInfoType::Certificate_Digest_With_SHA256);

    // Other receives certificate request and sends certificate with next message
    decap_confirm = other_security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(get_type(signer_info(encap_confirm.sec_packet)), SignerInfoType::Certificate);
}

TEST_F(SecurityEntityTest, verify_denm_without_generation_location)
{
    NaiveCertificateProvider other_provider(runtime);

    class NoLocationHeaderPolicy : public DefaultSignHeaderPolicy
    {
    public:
        NoLocationHeaderPolicy(const Runtime& rt, PositionProvider& positioning) :
            DefaultSignHeaderPolicy(rt, positioning), m_runtime(rt) {}

        std::list<HeaderField> prepare_header(const SignRequest& request, CertificateProvider& certificate_provider) override
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

    SignService sign = straight_sign_service(other_provider, *crypto_backend, other_policy);
    VerifyService verify = straight_verify_service(runtime, other_provider, *certificate_validator, *crypto_backend, cert_cache, other_policy, position_provider);
    DelegatingSecurityEntity other_security(sign, verify);

    its_aid = aid::DEN;
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
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

        std::list<HeaderField> prepare_header(const SignRequest& request, CertificateProvider& certificate_provider) override
        {
            std::list<HeaderField> header_fields;
            return header_fields;
        }
    } other_policy(runtime, position_provider);

    SignService sign = straight_sign_service(other_provider, *crypto_backend, other_policy);
    VerifyService verify = straight_verify_service(runtime, other_provider, *certificate_validator, *crypto_backend, cert_cache, other_policy, position_provider);
    DelegatingSecurityEntity other_security(sign, verify);

    its_aid = aid::DEN;
    EncapConfirm encap_confirm = other_security.encapsulate_packet(create_encap_request());
    ASSERT_EQ(nullptr, encap_confirm.sec_packet.header_field<HeaderFieldType::Its_Aid>());

    DecapConfirm decap_confirm = security.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(DecapReport::Incompatible_Protocol, decap_confirm.report);
}

// TODO add tests for Unsupported_Signer_Identifier_Type, Incompatible_Protocol
