#include <vanetza/security/persistence.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstdint>

using namespace vanetza::security;

#define ASSET(path) ASSET_DIR "/" path

namespace
{

const std::array<uint8_t, 32> expected_private_key = {
    0x53, 0xb7, 0x7e, 0xb8, 0x48, 0x2e, 0x3c, 0x1a,
    0xd3, 0x36, 0x70, 0xc0, 0xc6, 0xc4, 0x6b, 0xc0,
    0x36, 0x90, 0xd4, 0x00, 0x59, 0xd3, 0xcb, 0xb5,
    0x81, 0xb3, 0x36, 0xaf, 0x8a, 0x98, 0x93, 0xf4
};

void check_private_key(const PrivateKey& key)
{
    EXPECT_EQ(key.type, KeyType::NistP256);
    ASSERT_EQ(key.key.size(), expected_private_key.size());
    EXPECT_TRUE(std::equal(key.key.begin(), key.key.end(), expected_private_key.begin()));
}

} // namespace

#if defined VANETZA_WITH_OPENSSL || defined VANETZA_WITH_CRYPTOPP

TEST(Persistence, load_pem)
{
    check_private_key(load_private_key_from_pem_file(ASSET("test_key.pem")));
}

TEST(Persistence, load_der)
{
    check_private_key(load_private_key_from_der_file(ASSET("test_key.der")));
}

TEST(Persistence, pem_and_der_load_same_key)
{
    auto pem = load_private_key_from_pem_file(ASSET("test_key.pem"));
    auto der = load_private_key_from_der_file(ASSET("test_key.der"));
    EXPECT_EQ(pem.type, der.type);
    EXPECT_EQ(pem.key, der.key);
}

TEST(Persistence, load_pem_nonexistent_file)
{
    EXPECT_THROW(load_private_key_from_pem_file("nonexistent.pem"), std::runtime_error);
}

TEST(Persistence, load_der_nonexistent_file)
{
    EXPECT_THROW(load_private_key_from_der_file("nonexistent.der"), std::runtime_error);
}

#endif /* VANETZA_WITH_OPENSSL || VANETZA_WITH_CRYPTOPP */

#ifdef VANETZA_WITH_OPENSSL
TEST(Persistence, openssl_load_pem)
{
    check_private_key(load_private_key_from_pem_file_openssl(ASSET("test_key.pem")));
}

TEST(Persistence, openssl_load_der)
{
    check_private_key(load_private_key_from_der_file_openssl(ASSET("test_key.der")));
}
#endif /* VANETZA_WITH_OPENSSL */

#ifdef VANETZA_WITH_CRYPTOPP
TEST(Persistence, cryptopp_load_pem)
{
    check_private_key(load_private_key_from_pem_file_cryptopp(ASSET("test_key.pem")));
}

TEST(Persistence, cryptopp_load_der)
{
    check_private_key(load_private_key_from_der_file_cryptopp(ASSET("test_key.der")));
}
#endif /* VANETZA_WITH_CRYPTOPP */
