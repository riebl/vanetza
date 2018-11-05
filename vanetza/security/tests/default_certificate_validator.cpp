#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/trust_store.hpp>
#include <vanetza/units/angle.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::security;

class DefaultCertificateValidatorTest : public ::testing::Test
{
public:
    DefaultCertificateValidatorTest() :
        runtime(Clock::at("2016-08-01 00:00")),
        backend(create_backend("default")),
        cert_provider(runtime),
        cert_cache(runtime),
        cert_validator(*backend, cert_cache, trust_store)
    {
        trust_store.insert(cert_provider.root_certificate());
        cert_cache.insert(cert_provider.aa_certificate());
    }

protected:
    ManualRuntime runtime;
    std::unique_ptr<Backend> backend;
    NaiveCertificateProvider cert_provider;
    std::vector<Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    DefaultCertificateValidator cert_validator;
};

TEST_F(DefaultCertificateValidatorTest, invalid_signer_info)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.signer_info = cert_provider.own_chain().front();
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Invalid_Signer, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, missing_subject_assurance)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_attribute(SubjectAttributeType::Assurance_Level);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Missing_Subject_Assurance, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, inconsistent_subject_assurance)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_attribute(SubjectAttributeType::Assurance_Level);
    cert.subject_attributes.push_back(SubjectAssurance(0xE0)); // higher level
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Inconsistent_With_Signer, validity.reason());

    cert.remove_attribute(SubjectAttributeType::Assurance_Level);
    cert.subject_attributes.push_back(SubjectAssurance(0x03)); // same level, higher confidence
    cert_provider.sign_authorization_ticket(cert);

    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Inconsistent_With_Signer, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_no_constraint)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Broken_Time_Period, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    restriction.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_duration)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    StartAndDurationValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    restriction.duration = Duration(23, Duration::Units::Hours);
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    // all certificates must use time_start_and_end as restriction
    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    ASSERT_EQ(CertificateInvalidReason::Broken_Time_Period, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    EndValidity restriction = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    // all certificates must use time_start_and_end as restriction
    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    ASSERT_EQ(CertificateInvalidReason::Broken_Time_Period, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_two_constraints)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);
    // add first constraint
    StartAndEndValidity start_and_end_validity;
    start_and_end_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    start_and_end_validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(start_and_end_validity);
    // add second constraint
    StartAndDurationValidity start_and_duration_validity;
    start_and_duration_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    start_and_duration_validity.duration = Duration(23, Duration::Units::Hours);
    cert.validity_restriction.push_back(start_and_duration_validity);
    // re-sign certificate
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Broken_Time_Period, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_with_parent)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(3));
    restriction.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Inconsistent_With_Signer, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_start_and_end)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() + std::chrono::hours(3));
    restriction.end_validity = convert_time32(runtime.now() - std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Broken_Time_Period, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, reject_additional_permissions)
{
    Certificate cert = cert_provider.generate_authorization_ticket();

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);

    cert.add_permission(16513 /* deprecated, so won't be used */, ByteBuffer({}));
    cert_provider.sign_authorization_ticket(cert);

    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::Inconsistent_With_Signer, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, accept_permission_subset_permutation)
{
    // We test both orders here, so we're not dependent on changes to the certificate provider order.
    Certificate cert = cert_provider.generate_authorization_ticket();

    // Order 1
    cert.remove_attribute(SubjectAttributeType::ITS_AID_SSP_List);
    cert.add_permission(aid::GN_MGMT, ByteBuffer({}));
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);

    // Order 2
    cert.remove_attribute(SubjectAttributeType::ITS_AID_SSP_List);
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    cert.add_permission(aid::GN_MGMT, ByteBuffer({}));
    cert_provider.sign_authorization_ticket(cert);

    validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);

    // Definite subset
    cert.remove_attribute(SubjectAttributeType::ITS_AID_SSP_List);
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    cert_provider.sign_authorization_ticket(cert);

    validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);
}
