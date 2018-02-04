#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/trust_store.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::geonet;
using namespace vanetza::security;

class DefaultCertificateValidatorTest : public ::testing::Test
{
public:
    DefaultCertificateValidatorTest() :
        runtime(Clock::at("2016-08-01 00:00")),
        backend(create_backend("default")),
        cert_provider(runtime.now()),
        cert_cache(runtime),
        cert_validator(*backend, runtime.now(), trust_store, cert_cache)
    {
        trust_store.insert(cert_provider.root_certificate());
    }

protected:
    Runtime runtime;
    std::unique_ptr<Backend> backend;
    NaiveCertificateProvider cert_provider;
    std::vector<Certificate> roots;
    TrustStore trust_store;
    CertificateCache cert_cache;
    DefaultCertificateValidator cert_validator;
};

void certificate_remove_time_constraints(Certificate& cert)
{
    for (auto it = cert.validity_restriction.begin(); it != cert.validity_restriction.end(); ++it) {
        const ValidityRestriction& restriction = *it;
        ValidityRestrictionType type = get_type(restriction);
        switch (type) {
            case ValidityRestrictionType::Time_End:
            case ValidityRestrictionType::Time_Start_And_End:
            case ValidityRestrictionType::Time_Start_And_Duration:
                it = cert.validity_restriction.erase(it);
                break;
            default:
                break;
        }
    }
}

TEST_F(DefaultCertificateValidatorTest, validity_time_no_constraint)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);
    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    restriction.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Success, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_duration)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    StartAndDurationValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    restriction.duration = Duration(23, Duration::Units::Hours);
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Success, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    EndValidity restriction = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    // Time period broken, because AA and root CA have start time
    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Inconsistant_Chain, confirm.report);

    // TODO: Add test for certificate, AA and root CA with EndValidity
}

TEST_F(DefaultCertificateValidatorTest, validity_time_two_constraints)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    StartAndEndValidity start_and_end_validity;
    start_and_end_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    start_and_end_validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(start_and_end_validity);

    StartAndDurationValidity start_and_duration_validity;
    start_and_duration_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
    start_and_duration_validity.duration = Duration(23, Duration::Units::Hours);
    cert.validity_restriction.push_back(start_and_duration_validity);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_with_parent)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() - std::chrono::hours(3));
    restriction.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Inconsistant_Chain, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_start_and_end)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket();
    certificate_remove_time_constraints(cert);

    StartAndEndValidity restriction;
    restriction.start_validity = convert_time32(runtime.now() + std::chrono::hours(3));
    restriction.end_validity = convert_time32(runtime.now() - std::chrono::hours(23));
    cert.validity_restriction.push_back(restriction);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_region_without_position)
{
    Certificate cert = cert_provider.generate_authorization_ticket();

    TwoDLocation center {
        static_cast<geo_angle_i32t>(10 * units::degree),
        static_cast<geo_angle_i32t>(20 * units::degree)
    };

    CircularRegion region {
        center,
        static_cast<distance_u16t>(10 * units::si::meter)
    };

    cert.validity_restriction.push_back(region);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    auto confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_region_circle)
{
    Certificate cert = cert_provider.generate_authorization_ticket();

    TwoDLocation center {
        static_cast<geo_angle_i32t>(10 * units::degree),
        static_cast<geo_angle_i32t>(20 * units::degree)
    };

    CircularRegion region {
        center,
        static_cast<distance_u16t>(10 * units::si::meter)
    };

    cert.validity_restriction.push_back(region);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    DecapConfirm confirm;
    LongPositionVector lpv;
    lpv.position_accuracy_indicator = true;

    // inside
    lpv.latitude = static_cast<geo_angle_i32t>(10.000001 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(20 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Success, confirm.report);

    // outside
    lpv.latitude = static_cast<geo_angle_i32t>(10.1 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(20 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}

TEST_F(DefaultCertificateValidatorTest, validity_region_rectangle)
{
    Certificate cert = cert_provider.generate_authorization_ticket();

    TwoDLocation northwest {
        static_cast<geo_angle_i32t>(10 * units::degree),
        static_cast<geo_angle_i32t>(10 * units::degree)
    };

    TwoDLocation southeast {
        static_cast<geo_angle_i32t>(20 * units::degree),
        static_cast<geo_angle_i32t>(20 * units::degree)
    };

    RectangularRegion region {
        northwest,
        southeast
    };

    std::list<RectangularRegion> regions;
    regions.push_back(region);

    cert.validity_restriction.push_back(regions);

    cert_provider.sign_authorization_ticket(cert);

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    DecapConfirm confirm;
    LongPositionVector lpv;
    lpv.position_accuracy_indicator = true;

    // inside
    lpv.latitude = static_cast<geo_angle_i32t>(15 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(15 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Success, confirm.report);

    // outside - left
    lpv.latitude = static_cast<geo_angle_i32t>(9 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(15 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);

    // outside - right
    lpv.latitude = static_cast<geo_angle_i32t>(20.0001 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(15 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);

    // outside - top
    lpv.latitude = static_cast<geo_angle_i32t>(15 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(9 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);

    // outside - down
    lpv.latitude = static_cast<geo_angle_i32t>(15 * units::degree);
    lpv.longitude = static_cast<geo_angle_i32t>(21 * units::degree);
    cert_validator.update(lpv);

    confirm = cert_validator.check_certificate(cert);
    EXPECT_EQ(DecapReport::Invalid_Certificate, confirm.report);
}
