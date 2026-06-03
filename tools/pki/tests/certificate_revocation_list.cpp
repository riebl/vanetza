#include "certificate_revocation_list.hpp"
#include "crl_test_fixture.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include <gtest/gtest.h>

namespace vanetza
{
namespace pki
{

class CertificateRevocationListTest : public ::testing::Test
{
protected:
    CertificateRevocationListTest() :
        m_credentials(std::make_shared<MockCredentialStorage>()), m_security(m_credentials)
    {
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    OpenSslSecurityModule m_security;
};

TEST_F(CertificateRevocationListTest, decode_rejects_garbage)
{
    CertificateRevocationList crl;
    EXPECT_FALSE(crl.decode(ByteBuffer { 0x00, 0x01, 0x02, 0x03 }));
}

TEST_F(CertificateRevocationListTest, get_hashed_id8_returns_signer_digest)
{
    HashedId8 issuer = make_id(0xAB);
    CertificateRevocationList crl = build_test_crl(issuer, { make_id(0x11) });

    auto got = crl.get_hashed_id8(m_security);
    ASSERT_TRUE(got);
    EXPECT_EQ(issuer, *got);
}

TEST_F(CertificateRevocationListTest, revoked_entries_returns_list)
{
    HashedId8 a = make_id(0x11);
    HashedId8 b = make_id(0x22);
    HashedId8 c = make_id(0x33);
    CertificateRevocationList crl = build_test_crl(make_id(0xAB), { a, b, c });

    auto entries = crl.revoked_entries();
    ASSERT_TRUE(entries);
    ASSERT_EQ(3u, entries->size());
    EXPECT_EQ(a, (*entries)[0]);
    EXPECT_EQ(b, (*entries)[1]);
    EXPECT_EQ(c, (*entries)[2]);
}

TEST_F(CertificateRevocationListTest, revoked_entries_empty_is_valid)
{
    CertificateRevocationList crl = build_test_crl(make_id(0xAB), {});

    auto entries = crl.revoked_entries();
    ASSERT_TRUE(entries);
    EXPECT_TRUE(entries->empty());
}

TEST_F(CertificateRevocationListTest, encode_decode_roundtrip)
{
    HashedId8 issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);
    CertificateRevocationList original = build_test_crl(issuer, { revoked });

    ByteBuffer bytes = original.encode();
    CertificateRevocationList decoded;
    ASSERT_TRUE(decoded.decode(bytes));

    auto issuer_out = decoded.get_hashed_id8(m_security);
    ASSERT_TRUE(issuer_out);
    EXPECT_EQ(issuer, *issuer_out);

    auto entries = decoded.revoked_entries();
    ASSERT_TRUE(entries);
    ASSERT_EQ(1u, entries->size());
    EXPECT_EQ(revoked, (*entries)[0]);
}

} // namespace pki
} // namespace vanetza
