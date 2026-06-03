#include "credential_filesystem_storage.hpp"
#include <gtest/gtest.h>
#include <fstream>
#include <set>
#include <vector>

using namespace vanetza::pki;

static const std::string privKeyPem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIHlpKyVDNCQ2x5IFeBelQyyvANI8iTFIoCTfNARm1LVxoAoGCCqGSM49\n"
    "AwEHoUQDQgAEvfkk5CcwIqP29fGu9n6kXmojUpV2xUlnM2BwJMoYmiVU7lF9p7tu\n"
    "+KUbGlhPaYLN0UZ13KQTmi3gV3aLolyXUw==\n"
    "-----END EC PRIVATE KEY-----";

static const vanetza::ByteBuffer privKeyRaw = {
    0x18, 0xab, 0x8e, 0xcd, 0xf6, 0x5f, 0xb8, 0x06,
    0x3b, 0x24, 0xe5, 0xd6, 0x77, 0xf9, 0x47, 0x6a,
    0xd6, 0xef, 0x7b, 0x54, 0x0b, 0x8f, 0x2a, 0x15,
    0xe0, 0x09, 0x7c, 0x23, 0xe9, 0xf2, 0x73, 0x11
};

static const vanetza::ByteBuffer pubKeyRawX = {
    0x54, 0x80, 0xd4, 0x56, 0x9e, 0x50, 0x4d, 0x8e,
    0x1a, 0x14, 0xcc, 0x0e, 0xd7, 0xea, 0xd0, 0xcf,
    0x13, 0x49, 0xb8, 0x84, 0xa9, 0xb7, 0x9b, 0xe5,
    0x2f, 0x4a, 0x4c, 0xe1, 0x62, 0xa3, 0x75, 0xe4
};

static const vanetza::ByteBuffer pubKeyRawY = {
    0x95, 0x01, 0x22, 0x47, 0xb5, 0x7a, 0x32, 0xc0,
    0xd9, 0x3c, 0x61, 0x00, 0xd7, 0xe6, 0x7e, 0xe9,
    0x24, 0xe1, 0x40, 0x84, 0x77, 0x12, 0x7e, 0xa6,
    0x9f, 0x23, 0x7b, 0xda, 0x40, 0xd9, 0x09, 0x32
};

class CredentialFilesystemStorageTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        root = std::filesystem::temp_directory_path() / "pki_unit_test" / "credentials";
    }

    void TearDown() override
    {
        std::filesystem::remove_all(root);
    }

    std::filesystem::path root;
};

TEST_F(CredentialFilesystemStorageTest, store_and_fetch)
{
    CredentialFilesystemStorage storage(root);
    PublicKey pub;
    pub.type = KeyType::BrainpoolP256r1;
    pub.compression = KeyCompression::NoCompression;
    pub.x = pubKeyRawX;
    pub.y = pubKeyRawY;

    PrivateKey priv;
    priv.key = privKeyRaw;
    priv.type = KeyType::BrainpoolP256r1;

    const std::string filename = "025480D4569E504D8E1A14CC0ED7EAD0CF1349B884A9B79BE52F4A4CE162A375E4.pem";
    std::filesystem::remove(root / filename);
    EXPECT_FALSE(std::filesystem::is_regular_file(root / filename));
    EXPECT_FALSE(storage.fetch(pub));
    storage.store(pub, priv);
    boost::optional<PrivateKey> fetched = storage.fetch(pub);
    ASSERT_TRUE(fetched);
    EXPECT_EQ(priv.type, fetched->type);
    EXPECT_EQ(priv.key, fetched->key);
    EXPECT_TRUE(std::filesystem::is_regular_file(root / filename));
}

TEST_F(CredentialFilesystemStorageTest, list_yields_canonical_hex_stems_only)
{
    std::filesystem::create_directories(root);
    // Three valid-looking .pem files (P-256 stems = "02"/"03" + 64 hex chars).
    std::ofstream(root / "025480D4569E504D8E1A14CC0ED7EAD0CF1349B884A9B79BE52F4A4CE162A375E4.pem").put('x');
    std::ofstream(root / "030000000000000000000000000000000000000000000000000000000000000000.pem").put('x');
    std::ofstream(root / "021111111111111111111111111111111111111111111111111111111111111111.pem").put('x');
    // Decoys that must not appear in list():
    std::ofstream(root / "ignore.txt").put('x'); // wrong extension
    std::ofstream(root / "garbage.pem").put('x'); // wrong stem format
    std::ofstream(root / "025480D4569E504D8E1A14CC0ED7EAD0CF1349B884A9B79BE52F4A4CE162A375.pem")
        .put('x'); // 64 chars (one short)
    std::filesystem::create_directory(root / "subdir");

    CredentialFilesystemStorage storage(root);
    std::set<std::string> seen;
    for (const auto& name : storage.list()) {
        seen.insert(name);
    }

    EXPECT_EQ(3u, seen.size());
    EXPECT_TRUE(seen.count("025480D4569E504D8E1A14CC0ED7EAD0CF1349B884A9B79BE52F4A4CE162A375E4"));
    EXPECT_TRUE(seen.count("030000000000000000000000000000000000000000000000000000000000000000"));
    EXPECT_TRUE(seen.count("021111111111111111111111111111111111111111111111111111111111111111"));
}

TEST_F(CredentialFilesystemStorageTest, list_on_empty_directory)
{
    std::filesystem::create_directories(root);
    CredentialFilesystemStorage storage(root);
    std::vector<std::string> names;
    for (const auto& n : storage.list()) {
        names.push_back(n);
    }
    EXPECT_TRUE(names.empty());
}

TEST_F(CredentialFilesystemStorageTest, discard_by_name_removes_file)
{
    std::filesystem::create_directories(root);
    const std::string stem = "030000000000000000000000000000000000000000000000000000000000000000";
    std::ofstream(root / (stem + ".pem")).put('x');
    ASSERT_TRUE(std::filesystem::is_regular_file(root / (stem + ".pem")));

    CredentialFilesystemStorage storage(root);
    EXPECT_TRUE(storage.discard(stem));
    EXPECT_FALSE(std::filesystem::is_regular_file(root / (stem + ".pem")));
}

TEST_F(CredentialFilesystemStorageTest, discard_by_name_returns_false_for_unknown)
{
    std::filesystem::create_directories(root);
    CredentialFilesystemStorage storage(root);
    EXPECT_FALSE(storage.discard("020000000000000000000000000000000000000000000000000000000000000000"));
}