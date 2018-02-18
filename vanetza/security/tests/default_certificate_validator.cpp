#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
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
        cert_provider(runtime.now()),
        cert_cache(runtime),
        cert_validator(*backend, runtime.now(), position_provider, trust_store, cert_cache)
    {
        trust_store.insert(cert_provider.root_certificate());
        cert_cache.insert(cert_provider.aa_certificate());
    }

    void set_position(units::GeoAngle latitude, units::GeoAngle longitude)
    {
        PositionFix position;
        position.latitude = latitude;
        position.longitude = longitude;
        position.confidence.semi_minor = 50.0 * units::si::meter;
        position.confidence.semi_major = 50.0 * units::si::meter;
        position_provider.position_fix(position);
    }

protected:
    Runtime runtime;
    StoredPositionProvider position_provider;
    std::unique_ptr<Backend> backend;
    NaiveCertificateProvider cert_provider;
    std::vector<Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    DefaultCertificateValidator cert_validator;
};

TEST_F(DefaultCertificateValidatorTest, validity_time_no_constraint)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
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

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    cert.remove_restriction(ValidityRestrictionType::Time_Start_And_End);

    EndValidity restriction = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    // Time period broken, because AA and root CA have start time
    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::INCONSISTENT_WITH_SIGNER, validity.reason());

    // TODO: Add test for certificate, AA and root CA with EndValidity
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
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
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
    EXPECT_EQ(CertificateInvalidReason::INCONSISTENT_WITH_SIGNER, validity.reason());
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
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_region_without_position)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    TwoDLocation center { 10 * units::degree, 20 * units::degree };
    CircularRegion region { center, 10 * units::si::meter };
    cert.validity_restriction.push_back(region);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_region_circle)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    TwoDLocation center { 10 * units::degree, 20 * units::degree };
    CircularRegion region { center, 10 * units::si::meter };
    cert.validity_restriction.push_back(region);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity;
    TwoDLocation ego_pos;
    // inside
    set_position(10.000001 * units::degree,  20 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);

    // outside
    set_position(10.1 * units::degree, 20 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_region_rectangle)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    TwoDLocation northwest { 20 * units::degree, 10 * units::degree };
    TwoDLocation southeast { 10 * units::degree, 20 * units::degree };
    RectangularRegion region { northwest, southeast };
    std::list<RectangularRegion> regions;
    regions.push_back(region);
    cert.validity_restriction.push_back(regions);
    cert_provider.sign_authorization_ticket(cert);

    CertificateValidity validity;
    TwoDLocation ego_pos;

    // inside
    set_position(15 * units::degree, 15 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);

    // outside - left
    set_position(15 * units::degree, 9 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());

    // outside - right
    set_position(15 * units::degree, 21 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());

    // outside - top
    set_position(21 * units::degree, 15 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());

    // outside - down
    set_position(9 * units::degree, 15 * units::degree);
    validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::OFF_REGION, validity.reason());
}
