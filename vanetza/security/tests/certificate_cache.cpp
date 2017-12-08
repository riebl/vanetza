#include <gtest/gtest.h>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/tests/serialization.hpp>

using namespace vanetza;
using namespace vanetza::security;

TEST(CertificateCacheTest, lookup)
{
    const char str[] =
        "02015388DEC640C6E19E010052000004B27D4D442F58E065F8D500478929BC843940F3C34D46C547"
        "5803C03594E35BD7E0132FD01634E86D4F50F7F2366988E12525232D00D03E98FC21CA8E5D0AF370"
        "02E0210B24030100002504010000000B0114E9DB83154CBC0203000000553C8D2B8A4E53F3D84A88"
        "37BEEBE83D5C7F68484AC5EFCEEFCC7B0BC5E9531754AAF58BF90790A10F2FD11796A85E13DFFAAC"
        "6073D2068465DA733994CD0C71";

    Clock::time_point now = Clock::at("2016-08-01 00:00");
    CertificateCache cache(now);
    Certificate cert;

    deserialize_from_hexstring(str, cert);

    // empty cache
    EXPECT_EQ(0, cache.lookup(calculate_hash(cert)).size());

    cache.insert(cert);

    // cache only contains 'cert' and must be able to find it
    EXPECT_EQ(1, cache.lookup(calculate_hash(cert)).size());

    // expiration time is two seconds
    now += std::chrono::seconds(3);

    // required, as eviction happens after lookup
    EXPECT_EQ(0, cache.lookup(HashedId8({ 0, 0, 0, 0, 0, 0, 0, 0 })).size());

    // previous lookup should have cleared 'cert'
    EXPECT_EQ(0, cache.lookup(calculate_hash(cert)).size());
}
