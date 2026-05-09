#include <vanetza/common/byte_order.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/geodesy/country_database.hpp>
#include <vanetza/geonet/units.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/location_checker.hpp>
#include <vanetza/security/v3/naive_certificate_provider.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <gtest/gtest.h>
#include <cstring>

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
    struct Vanetza_Security_RectangularRegion* rectReg = vanetza::asn1::allocate<Vanetza_Security_RectangularRegion_t>();
    rectReg->northWest.longitude = 84044170;
    rectReg->northWest.latitude = 490144200;
    rectReg->southEast.longitude = 84044170;
    rectReg->southEast.latitude = 490144200;
    // Re-allocate the structure
    vanetza::asn1::free(asn_DEF_Vanetza_Security_GeographicRegion, cert->toBeSigned.region);
    region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
    region->present = Vanetza_Security_GeographicRegion_PR_rectangularRegion;
    cert->toBeSigned.region = region;
    asn_sequence_add(&region->choice.rectangularRegion, rectReg);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // Valid rectangular area
    asn_sequence_empty(&region->choice.rectangularRegion);
    rectReg->northWest.longitude = 83506870;
    rectReg->northWest.latitude = 490464060;
    rectReg->southEast.longitude = 84234710;
    rectReg->southEast.latitude = 489982120;
    asn_sequence_add(&region->choice.rectangularRegion, rectReg);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);

    // IdentifiedRegion — flag OFF (default conservative behaviour): OutsideRegion
    {
        DefaultLocationChecker strictChecker;
        // permissive_identified_region_ defaults to false
        cert_validator.use_location_checker(&strictChecker);
        vanetza::asn1::free(asn_DEF_Vanetza_Security_GeographicRegion, cert->toBeSigned.region);
        region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
        region->present = Vanetza_Security_GeographicRegion_PR_identifiedRegion;
        cert->toBeSigned.region = region;
        validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
        EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);
    }

    // IdentifiedRegion — flag ON (operator opt-in permissive fallback, issue #262): Valid
    {
        DefaultLocationChecker permissiveChecker;
        permissiveChecker.set_permissive_identified_region(true);
        cert_validator.use_location_checker(&permissiveChecker);
        vanetza::asn1::free(asn_DEF_Vanetza_Security_GeographicRegion, cert->toBeSigned.region);
        region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
        region->present = Vanetza_Security_GeographicRegion_PR_identifiedRegion;
        cert->toBeSigned.region = region;
        validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
        EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);
        cert_validator.use_location_checker(&defaultLocationChecker);
    }
}

namespace
{

template<vanetza::ByteOrder Order, typename T>
void append(std::vector<uint8_t>& buf, T v)
{
    vanetza::EndianType<T, Order> e;
    e = vanetza::host_cast(v);
    auto raw = e.get();
    const auto* p = reinterpret_cast<const uint8_t*>(&raw);
    buf.insert(buf.end(), p, p + sizeof(raw));
}

void append_u16le(std::vector<uint8_t>& buf, uint16_t v)
{
    append<vanetza::ByteOrder::LittleEndian>(buf, v);
}

void append_u32le(std::vector<uint8_t>& buf, uint32_t v)
{
    append<vanetza::ByteOrder::LittleEndian>(buf, v);
}

void append_f64le(std::vector<uint8_t>& buf, double v)
{
    uint64_t bits;
    std::memcpy(&bits, &v, sizeof(bits));
    append<vanetza::ByteOrder::LittleEndian>(buf, bits);
}

// Build a country data binary with Germany bounding box around Karlsruhe (test position: 49.014, 8.404)
std::vector<uint8_t> make_germany_data()
{
    std::vector<uint8_t> wkb;
    wkb.push_back(0x01); // LE
    append_u32le(wkb, 3);  // Polygon
    append_u32le(wkb, 1);  // 1 ring
    append_u32le(wkb, 5);  // 5 points (closed)
    double ring[][2] = {{5.9, 47.3}, {15.0, 47.3}, {15.0, 55.1}, {5.9, 55.1}, {5.9, 47.3}};
    for (const auto& p : ring) {
        append_f64le(wkb, p[0]);
        append_f64le(wkb, p[1]);
    }

    std::vector<uint8_t> data;
    append_u16le(data, 1); // format version
    append_u16le(data, 276); // Germany M.49
    append_u32le(data, static_cast<uint32_t>(wkb.size()));
    data.insert(data.end(), wkb.begin(), wkb.end());
    return data;
}

} // anonymous namespace

TEST_F(DefaultCertificateValidatorTest, identified_region_country_only_with_database)
{
    auto country_data = make_germany_data();
    geodesy::CountryDatabase country_db;
    ASSERT_TRUE(country_db.load(country_data.data(), country_data.size()));

    Certificate cert = cert_provider.generate_authorization_ticket();
    auto* region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
    region->present = Vanetza_Security_GeographicRegion_PR_identifiedRegion;
    cert->toBeSigned.region = region;

    auto* id_region = vanetza::asn1::allocate<Vanetza_Security_IdentifiedRegion_t>();
    id_region->present = Vanetza_Security_IdentifiedRegion_PR_countryOnly;
    id_region->choice.countryOnly = 276;
    asn_sequence_add(&region->choice.identifiedRegion, id_region);

    // With database: position (49.014, 8.404) is inside Germany box
    DefaultLocationChecker checker;
    checker.use_country_database(&country_db);
    cert_validator.use_location_checker(&checker);
    auto validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);

    // Change country to France (250), not in database, permissive=false
    id_region->choice.countryOnly = 250;
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // Same but with permissive=true (still reject with countryOnly)
    checker.set_permissive_identified_region(true);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);
}

TEST_F(DefaultCertificateValidatorTest, identified_region_without_database_permissive)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    auto* region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
    region->present = Vanetza_Security_GeographicRegion_PR_identifiedRegion;
    cert->toBeSigned.region = region;

    auto* id_region = vanetza::asn1::allocate<Vanetza_Security_IdentifiedRegion_t>();
    id_region->present = Vanetza_Security_IdentifiedRegion_PR_countryOnly;
    id_region->choice.countryOnly = 276;
    asn_sequence_add(&region->choice.identifiedRegion, id_region);

    // No database, permissive=false
    DefaultLocationChecker checker;
    cert_validator.use_location_checker(&checker);
    auto validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    // No database, permissive=true
    checker.set_permissive_identified_region(true);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);
}

TEST_F(DefaultCertificateValidatorTest, identified_region_country_and_regions_fallback)
{
    Certificate cert = cert_provider.generate_authorization_ticket();
    auto* region = vanetza::asn1::allocate<vanetza::security::v3::asn1::GeographicRegion>();
    region->present = Vanetza_Security_GeographicRegion_PR_identifiedRegion;
    cert->toBeSigned.region = region;

    auto* id_region = vanetza::asn1::allocate<Vanetza_Security_IdentifiedRegion_t>();
    id_region->present = Vanetza_Security_IdentifiedRegion_PR_countryAndRegions;
    id_region->choice.countryAndRegions.countryOnly = 276;
    asn_sequence_add(&region->choice.identifiedRegion, id_region);

    // countryAndRegions always falls back to permissive regardless of database
    DefaultLocationChecker checker;
    checker.set_permissive_identified_region(false);
    cert_validator.use_location_checker(&checker);
    auto validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::OutsideRegion, validity);

    checker.set_permissive_identified_region(true);
    validity = cert_validator.valid_for_signing(cert, vanetza::aid::CA);
    EXPECT_EQ(CertificateValidator::Verdict::Valid, validity);
}

