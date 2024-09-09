#include <gtest/gtest.h>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>

using namespace vanetza;
using namespace vanetza::security;

TEST(CertificateV3, cache)
{
    v3::CertificateCache cache;
    cache.store(v3::fake_certificate());
}