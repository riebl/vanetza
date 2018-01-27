#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <vanetza/security/trust_store.hpp>
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
    Certificate cert = cert_provider.generate_authorization_ticket([](Certificate& cert) {
        certificate_remove_time_constraints(cert);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        StartAndEndValidity validity;
        validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
        validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
        cert.validity_restriction.push_back(validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_start_and_duration)
{
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        StartAndDurationValidity validity;
        validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
        validity.duration = Duration(23, Duration::Units::Hours);
        cert.validity_restriction.push_back(validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_TRUE(validity);
}

TEST_F(DefaultCertificateValidatorTest, validity_time_end)
{
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        EndValidity validity = convert_time32(runtime.now() + std::chrono::hours(23));
        cert.validity_restriction.push_back(validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    // Time period broken, because AA and root CA have start time
    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());

    // TODO: Add test for certificate, AA and root CA with EndValidity
}

TEST_F(DefaultCertificateValidatorTest, validity_time_two_constraints)
{
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        StartAndEndValidity start_and_end_validity;
        start_and_end_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
        start_and_end_validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
        cert.validity_restriction.push_back(start_and_end_validity);

        StartAndDurationValidity start_and_duration_validity;
        start_and_duration_validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(1));
        start_and_duration_validity.duration = Duration(23, Duration::Units::Hours);
        cert.validity_restriction.push_back(start_and_duration_validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_with_parent)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        StartAndEndValidity validity;
        validity.start_validity = convert_time32(runtime.now() - std::chrono::hours(3));
        validity.end_validity = convert_time32(runtime.now() + std::chrono::hours(23));
        cert.validity_restriction.push_back(validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
}

TEST_F(DefaultCertificateValidatorTest, validity_time_consistency_start_and_end)
{
    // The generated authorization ticket's start time is prior to the AA certificate's start time
    Certificate cert = cert_provider.generate_authorization_ticket([this](Certificate& cert) {
        certificate_remove_time_constraints(cert);

        StartAndEndValidity validity;
        validity.start_validity = convert_time32(runtime.now() + std::chrono::hours(3));
        validity.end_validity = convert_time32(runtime.now() - std::chrono::hours(23));
        cert.validity_restriction.push_back(validity);
    });

    cert_cache.insert(cert_provider.aa_certificate());
    cert_cache.insert(cert_provider.root_certificate());

    CertificateValidity validity = cert_validator.check_certificate(cert);
    ASSERT_FALSE(validity);
    EXPECT_EQ(CertificateInvalidReason::BROKEN_TIME_PERIOD, validity.reason());
}
