#include <gtest/gtest.h>
#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/signer_info.hpp>
#include <vanetza/security/v2/tests/check_signature.hpp>
#include <vanetza/security/v2/tests/check_signer_info.hpp>
#include <vanetza/security/tests/serialization.hpp>

using vanetza::random_byte_sequence;
using vanetza::security::create_random_ecdsa_signature;
using vanetza::security::HashedId8;
using namespace vanetza::security::v2;

TEST(SignerInfo, Serialization)
{
    std::list<Certificate> certificates;
    Certificate a;
    a.signature = create_random_ecdsa_signature(28);
    Certificate b;
    b.signature = create_random_ecdsa_signature(29);
    certificates.push_back(a);
    certificates.push_back(b);
    SignerInfo info { certificates };

    check(info, serialize_roundtrip(info));
}

TEST(SignerInfo, WebValidator_Size)
{
    SignerInfo info;
    HashedId8 id {{ 0xA8, 0xED, 0x6D, 0xF6, 0x5B, 0x0E, 0x6D, 0x6A }};
    info = id;

    EXPECT_EQ(9, get_size(info));
}

TEST(SignerInfo, certificate_id_self)
{
    SignerInfo info { nullptr };
    EXPECT_FALSE(get_certificate_id(info));
    EXPECT_EQ(nullptr, get_certificate(info));
}

TEST(SignerInfo, certificate_id_digest)
{
    HashedId8 digest = {{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    SignerInfo info { digest };
    ASSERT_TRUE(get_certificate_id(info));
    EXPECT_EQ(digest, *get_certificate_id(info));
    EXPECT_EQ(nullptr, get_certificate(info));
}

TEST(SignerInfo, certificate_id_certificate)
{
    Certificate cert;
    cert.signature = create_random_ecdsa_signature(1);

    SignerInfo info { cert };
    ASSERT_TRUE(get_certificate_id(info));
    EXPECT_EQ(calculate_hash(cert), *get_certificate_id(info));
    ASSERT_NE(nullptr, get_certificate(info));
    EXPECT_EQ(calculate_hash(cert), calculate_hash(*get_certificate(info)));
}

TEST(SignerInfo, certificate_id_chain)
{
    Certificate aa;
    aa.signature = create_random_ecdsa_signature(2);
    Certificate at;
    at.signature = create_random_ecdsa_signature(3);

    // signer is the last certificate in chain
    SignerInfo info { std::list<Certificate> { aa, at } };
    ASSERT_TRUE(get_certificate_id(info));
    EXPECT_EQ(calculate_hash(at), *get_certificate_id(info));
    ASSERT_NE(nullptr, get_certificate(info));
    EXPECT_EQ(calculate_hash(at), calculate_hash(*get_certificate(info)));
}

TEST(SignerInfo, certificate_id_empty_chain)
{
    SignerInfo info { std::list<Certificate> {} };
    EXPECT_FALSE(get_certificate_id(info));
    EXPECT_EQ(nullptr, get_certificate(info));
}

TEST(SignerInfo, certificate_id_other_algorithm)
{
    CertificateDigestWithOtherAlgorithm other;
    other.algorithm = PublicKeyAlgorithm::ECIES_NISTP256;
    other.digest = {{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    SignerInfo info { other };
    // digest identifies the certificate even if we cannot verify it
    ASSERT_TRUE(get_certificate_id(info));
    EXPECT_EQ(other.digest, *get_certificate_id(info));
    EXPECT_EQ(nullptr, get_certificate(info));
}
