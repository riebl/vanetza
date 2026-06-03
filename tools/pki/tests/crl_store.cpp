#include "crl_store.hpp"
#include "certificate_revocation_list.hpp"
#include "crl_test_fixture.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include <gtest/gtest.h>
#include <fstream>

namespace vanetza
{
namespace pki
{

class CrlFilesystemStoreTest : public ::testing::Test
{
protected:
    CrlFilesystemStoreTest() :
        m_credentials(std::make_shared<MockCredentialStorage>()),
        m_security(std::make_shared<OpenSslSecurityModule>(m_credentials))
    {
    }

    void SetUp() override
    {
        m_root = std::filesystem::temp_directory_path() / "pki_unit_test" / "crl_store";
        std::filesystem::remove_all(m_root);
    }

    void TearDown() override
    {
        std::filesystem::remove_all(m_root);
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    std::shared_ptr<OpenSslSecurityModule> m_security;
    std::filesystem::path m_root;
};

TEST_F(CrlFilesystemStoreTest, store_and_lookup_roundtrip)
{
    HashedId8 issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);
    CertificateRevocationList crl = build_test_crl(issuer, { revoked });

    CrlFilesystemStore store(m_security, m_root);
    ASSERT_TRUE(store.store(crl));
    EXPECT_TRUE(store.is_revoked(issuer.octets, revoked.octets));
}

TEST_F(CrlFilesystemStoreTest, is_revoked_returns_false_for_unknown_issuer)
{
    CrlFilesystemStore store(m_security, m_root);
    HashedId8 known_issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);
    ASSERT_TRUE(store.store(build_test_crl(known_issuer, { revoked })));

    HashedId8 other_issuer = make_id(0xCD);
    EXPECT_FALSE(store.is_revoked(other_issuer.octets, revoked.octets));
}

TEST_F(CrlFilesystemStoreTest, is_revoked_returns_false_for_unlisted_cert)
{
    CrlFilesystemStore store(m_security, m_root);
    HashedId8 issuer = make_id(0xAB);
    ASSERT_TRUE(store.store(build_test_crl(issuer, { make_id(0x42) })));

    HashedId8 other_cert = make_id(0x99);
    EXPECT_FALSE(store.is_revoked(issuer.octets, other_cert.octets));
}

TEST_F(CrlFilesystemStoreTest, empty_crl_clears_prior_entries)
{
    HashedId8 issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);

    CrlFilesystemStore store(m_security, m_root);
    ASSERT_TRUE(store.store(build_test_crl(issuer, { revoked })));
    ASSERT_TRUE(store.is_revoked(issuer.octets, revoked.octets));

    ASSERT_TRUE(store.store(build_test_crl(issuer, {})));
    EXPECT_FALSE(store.is_revoked(issuer.octets, revoked.octets));
}

TEST_F(CrlFilesystemStoreTest, constructor_loads_existing_crl_files)
{
    HashedId8 issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);

    {
        CrlFilesystemStore writer(m_security, m_root);
        ASSERT_TRUE(writer.store(build_test_crl(issuer, { revoked })));
    }

    CrlFilesystemStore reader(m_security, m_root);
    EXPECT_TRUE(reader.is_revoked(issuer.octets, revoked.octets));
}

TEST_F(CrlFilesystemStoreTest, constructor_ignores_non_crl_files_and_garbage)
{
    std::filesystem::create_directories(m_root);
    std::ofstream(m_root / "not_a_crl.txt") << "ignored";
    std::ofstream(m_root / "garbage.crl") << "\x00\x01\x02";

    HashedId8 issuer = make_id(0xAB);
    HashedId8 revoked = make_id(0x42);
    {
        CrlFilesystemStore writer(m_security, m_root);
        ASSERT_TRUE(writer.store(build_test_crl(issuer, { revoked })));
    }

    CrlFilesystemStore reader(m_security, m_root);
    EXPECT_TRUE(reader.is_revoked(issuer.octets, revoked.octets));
}

} // namespace pki
} // namespace vanetza
