#include <gtest/gtest.h>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/sha.hpp>

using namespace vanetza;
using namespace vanetza::security;

// implicit certificate (IEEE 1609.2 clause 6.4.5) with a dummy reconstruction value
inline v3::Certificate fake_implicit_certificate()
{
  v3::Certificate cert;
    cert->version = 3;
    cert->type = Vanetza_Security_CertificateType_implicit;
    cert->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    std::array<char, 8> issuer_digest = { 1, 2, 3, 4, 5, 6, 7, 8 };
    OCTET_STRING_fromBuf(&cert->issuer.choice.sha256AndDigest, issuer_digest.data(), issuer_digest.size());
    cert->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
    std::array<char, 3> craca_id = { 0, 0, 0 };
    OCTET_STRING_fromBuf(&cert->toBeSigned.cracaId, craca_id.data(), craca_id.size());
    cert->toBeSigned.crlSeries = 0;
    cert->toBeSigned.validityPeriod.start = 0;
    cert->toBeSigned.validityPeriod.duration.present = Vanetza_Security_Duration_PR_minutes;
    cert->toBeSigned.validityPeriod.duration.choice.minutes = 10080;
    cert->toBeSigned.verifyKeyIndicator.present = Vanetza_Security_VerificationKeyIndicator_PR_reconstructionValue;
    cert->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.present = Vanetza_Security_EccP256CurvePoint_PR_compressed_y_0;
    std::array<char, 32> dummy_point {};
    OCTET_STRING_fromBuf(
        &cert->toBeSigned.verifyKeyIndicator.choice.reconstructionValue.choice.compressed_y_0,
        dummy_point.data(), dummy_point.size()
    );
    cert.add_app_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    return cert;
}

TEST(CertificateV3, cache)
{
    v3::CertificateCache cache;
    cache.store(v3::fake_certificate());
}

TEST(CertificateV3, implicit_certificate_digest)
{
    v3::Certificate cert = fake_implicit_certificate();
    ASSERT_TRUE(v3::is_canonical(*cert));

    // curve of a reconstructed key is unknown without the issuer certificate
    EXPECT_EQ(KeyType::Unspecified, cert.get_verification_key_type());
    // ECQV public key reconstruction is not supported
    EXPECT_FALSE(v3::get_public_key(*cert));

    // IEEE 1609.2 clause 5.3.2: SHA-256 over the canonical encoding
    const ByteBuffer encoded = cert.encode();
    const HashedId8 expected = create_hashed_id8(calculate_sha256_digest(encoded.data(), encoded.size()));
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);
    EXPECT_EQ(expected, *digest);
}

// build a certificate whose validity period starts at `start` and lasts for the given duration
inline v3::Certificate make_validity_duration(v3::Time32 start, Vanetza_Security_Duration_PR unit, long value)
{
    v3::Certificate cert = fake_implicit_certificate();
    auto& period = cert->toBeSigned.validityPeriod;
    period.start = start;
    period.duration.present = unit;
    switch (unit)
    {
    case Vanetza_Security_Duration_PR_microseconds:
        period.duration.choice.microseconds = value;
        break;
    case Vanetza_Security_Duration_PR_milliseconds:
        period.duration.choice.milliseconds = value;
        break;
    case Vanetza_Security_Duration_PR_seconds:
        period.duration.choice.seconds = value;
        break;
    case Vanetza_Security_Duration_PR_minutes:
        period.duration.choice.minutes = value;
        break;
    case Vanetza_Security_Duration_PR_hours:
        period.duration.choice.hours = value;
        break;
    case Vanetza_Security_Duration_PR_sixtyHours:
        period.duration.choice.sixtyHours = value;
        break;
    case Vanetza_Security_Duration_PR_years:
        period.duration.choice.years = value;
        break;
    default:
        break;
    }
    return cert;
}

TEST(CertificateV3, validity_duration_units)
{
    const v3::Time32 start = 1000;
    auto end = [start](Vanetza_Security_Duration_PR unit, long value) {
        return make_validity_duration(start, unit, value).get_start_and_end_validity().end_validity;
    };

    EXPECT_EQ(start, end(Vanetza_Security_Duration_PR_NOTHING, 0));
    EXPECT_EQ(start + 500, end(Vanetza_Security_Duration_PR_seconds, 500));
    EXPECT_EQ(start + 10 * 60, end(Vanetza_Security_Duration_PR_minutes, 10));
    EXPECT_EQ(start + 2 * 60 * 60, end(Vanetza_Security_Duration_PR_hours, 2));
    EXPECT_EQ(start + 60 * 60 * 60, end(Vanetza_Security_Duration_PR_sixtyHours, 1));
    EXPECT_EQ(start + 60 * 60 * 24 * 365, end(Vanetza_Security_Duration_PR_years, 1));

    // sub-second units truncate towards zero
    EXPECT_EQ(start + 5, end(Vanetza_Security_Duration_PR_milliseconds, 5000));
    EXPECT_EQ(start + 2, end(Vanetza_Security_Duration_PR_microseconds, 2000000));

    // huge durations overflow Time32 but are not undefined behaviour
    EXPECT_EQ(start + 1377453056, end(Vanetza_Security_Duration_PR_years, 8760));
}
