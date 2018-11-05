#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/security/certificate_cache.hpp>
#include <vanetza/security/tests/serialization.hpp>

using namespace vanetza;
using namespace vanetza::security;

class CertificateCacheTest : public ::testing::Test
{
public:
    CertificateCacheTest() :
        runtime(Clock::at("2018-01-03 17:15")),
        cache(runtime)
    {
    }

    Certificate build_certificate(SubjectType subject_type, uint8_t id = 0)
    {
        Certificate cert;
        cert.subject_info.subject_type = subject_type;
        cert.signer_info = HashedId8 {{ id, id, id, id, id, id, id, id }};
        EcdsaSignature signature;
        X_Coordinate_Only x_only;;
        x_only.x.insert(x_only.x.end(), 32, 0x22);
        signature.R = std::move(x_only);
        signature.s.insert(signature.s.end(), 32, 0x11);
        cert.signature = std::move(signature);
        return cert;
    }

protected:
    ManualRuntime runtime;
    CertificateCache cache;
};

static const HashedId8 zero_id = {{ 0, 0, 0, 0, 0, 0, 0, 0 }};

TEST_F(CertificateCacheTest, lookup)
{
    const Certificate cert = build_certificate(SubjectType::Authorization_Ticket);
    const HashedId8 cert_id = calculate_hash(cert);

    // empty cache
    EXPECT_EQ(0, cache.lookup(cert_id, SubjectType::Authorization_Ticket).size());

    cache.insert(cert);

    // cache only contains 'cert' and must be able to find it
    EXPECT_EQ(1, cache.lookup(cert_id, SubjectType::Authorization_Ticket).size());

    // cache only contains 'cert' and must not return it for other types
    EXPECT_EQ(0, cache.lookup(cert_id, SubjectType::Authorization_Authority).size());

    // but nothing else
    HashedId8 other_id = cert_id;
    other_id[3] = cert_id[3] + 1;
    EXPECT_EQ(0, cache.lookup(other_id, SubjectType::Authorization_Ticket).size());
}

TEST_F(CertificateCacheTest, insert_only_some_subject_type)
{
    cache.insert(build_certificate(SubjectType::Enrollment_Credential));
    EXPECT_EQ(0, cache.size());
    cache.insert(build_certificate(SubjectType::Authorization_Ticket));
    EXPECT_EQ(1, cache.size());
    cache.insert(build_certificate(SubjectType::Authorization_Authority));
    EXPECT_EQ(2, cache.size());
    cache.insert(build_certificate(SubjectType::Enrollment_Authority));
    EXPECT_EQ(2, cache.size());
    cache.insert(build_certificate(SubjectType::Root_CA));
    EXPECT_EQ(2, cache.size());
    cache.insert(build_certificate(SubjectType::CRL_Signer));
    EXPECT_EQ(2, cache.size());
}

TEST_F(CertificateCacheTest, drop_expired)
{
    const Certificate cert1 = build_certificate(SubjectType::Authorization_Ticket); // 2 seconds
    const Certificate cert2 = build_certificate(SubjectType::Authorization_Authority); // 1 hour
    ASSERT_NE(calculate_hash(cert1), calculate_hash(cert2));
    cache.insert(cert1);
    cache.insert(cert2);
    ASSERT_EQ(2, cache.size());

    runtime.trigger(std::chrono::seconds(3));
    EXPECT_EQ(2, cache.size());
    cache.lookup(zero_id, SubjectType::Authorization_Ticket); // any lookup drops expired cache entries
    EXPECT_EQ(1, cache.size());

    runtime.trigger(std::chrono::minutes(60));
    cache.lookup(zero_id, SubjectType::Authorization_Ticket);
    EXPECT_EQ(0, cache.size());
}

TEST_F(CertificateCacheTest, lookup_match_extends_lifetime)
{
    const Certificate cert1 = build_certificate(SubjectType::Authorization_Ticket);
    const Certificate cert2 = build_certificate(SubjectType::Authorization_Authority);
    const HashedId8 id_cert2 = calculate_hash(cert2);

    cache.insert(cert1);
    cache.insert(cert2);
    EXPECT_EQ(2, cache.size());

    for (unsigned i = 0; i < 3601; ++i) {
        runtime.trigger(std::chrono::seconds(1));
        cache.lookup(id_cert2, SubjectType::Authorization_Authority);
    }
    EXPECT_EQ(1, cache.size());
    EXPECT_EQ(1, cache.lookup(id_cert2, SubjectType::Authorization_Authority).size());
}

TEST_F(CertificateCacheTest, insert_extends_lifetime)
{
    const Certificate cert = build_certificate(SubjectType::Authorization_Ticket);
    const HashedId8 id = calculate_hash(cert);
    EXPECT_NE(zero_id, id);

    cache.insert(cert);
    EXPECT_EQ(1, cache.size());

    runtime.trigger(std::chrono::seconds(1));
    cache.insert(cert);
    EXPECT_EQ(1, cache.size());

    cache.lookup(zero_id, SubjectType::Authorization_Ticket);
    EXPECT_EQ(1, cache.size());

    runtime.trigger(std::chrono::seconds(2));
    cache.lookup(id, SubjectType::Authorization_Ticket);
    EXPECT_EQ(1, cache.size());
}
