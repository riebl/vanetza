#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/geonet/units.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/location_checker.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v3;

class DefaultCertificateValidatorTest : public ::testing::Test
{
public:
    DefaultCertificateValidatorTest() :
        runtime(Clock::at("2016-08-01 00:00")),
        backend(create_backend("default")),
        cert_provider(runtime),
        cert_cache()
    {
        cert_validator.use_runtime(&runtime);
        cert_validator.use_certificate_cache(&cert_cache);

        PositionFix position_fix;
        position_fix.latitude = 49.014420 * units::degree;
        position_fix.longitude = 8.404417 * units::degree;
        position_fix.confidence.semi_major = 25.0 * units::si::meter;
        position_fix.confidence.semi_minor = 25.0 * units::si::meter;
        assert(position_fix.confidence);
        position_provider.position_fix(position_fix);
        cert_validator.use_position_provider(&position_provider);

        trust_store.insert(cert_provider.root_certificate());
        cert_cache.store(cert_provider.aa_certificate());
    }

protected:
    ManualRuntime runtime;
    StoredPositionProvider position_provider;
    std::unique_ptr<Backend> backend;
    NaiveCertificateProvider cert_provider;
    TrustStore trust_store;
    CertificateCache cert_cache;
    DefaultCertificateValidator cert_validator;
};



TEST_F(DefaultCertificateValidatorTest, region_validator)
{
    Certificate cert = cert_provider.generate_authorization_ticket();

    cert_validator.disable_location_checks(true);
    CertificateValidator::Verdict validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    // Location checks are disabled
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);

    cert_validator.disable_location_checks(false);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    // No location checker was provided
    EXPECT_EQ(CertificateValidator::Verdict::Misconfiguration, validity);

    vanetza::security::v3::asn1::GeographicRegion* region = cert->toBeSigned.region;
    if (!region) {
        region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
        cert->toBeSigned.region = region;
    }
    region->present = Vanetza_Security_GeographicRegion_PR_circularRegion;
    region->choice.circularRegion.center.latitude = 12564.0;
    region->choice.circularRegion.center.longitude = 654321.0;
    region->choice.circularRegion.radius = 1337.0;

    // Always fail
    DenyLocationChecker denyLocationChecker;
    cert_validator.use_location_checker(&denyLocationChecker);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // Always success
    AllowLocationChecker allowLocationChecker;
    cert_validator.use_location_checker(&allowLocationChecker);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);

    // Actual check - invalid circular area
    DefaultLocationChecker defaultLocationChecker;
    cert_validator.use_location_checker(&defaultLocationChecker);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // Valid circular area
    vanetza::security::v3::asn1::CircularRegion& reg = region->choice.circularRegion;
    reg.center.latitude = 490144200;
    reg.center.longitude = 84044170;
    reg.radius = 1000;
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);

    // Invalid rectangular area
    region->present = Vanetza_Security_GeographicRegion_PR_rectangularRegion;
    struct Vanetza_Security_RectangularRegion* rectReg = vanetza::asn1::allocate<Vanetza_Security_RectangularRegion_t>();
    rectReg->northWest.longitude = 84044170;
    rectReg->northWest.latitude = 490144200;
    rectReg->southEast.longitude = 84044170;
    rectReg->southEast.latitude = 490144200;
    // Re-allocate the structure
    region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
    cert->toBeSigned.region = region;
    asn_sequence_add(&region->choice.rectangularRegion, rectReg);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // Valid rectangular area
    asn_sequence_empty(&region->choice.rectangularRegion);
    rectReg->northWest.longitude = 80000000;
    rectReg->northWest.latitude = 491000000;
    rectReg->southEast.longitude = 81000000;
    rectReg->southEast.latitude = 490000000;
    asn_sequence_add(&region->choice.rectangularRegion, rectReg);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);
}

