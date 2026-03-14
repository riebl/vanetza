#include <vanetza/security/persistence.hpp>
#include <vanetza/security/v2/persistence.hpp>
#include <vanetza/security/v3/persistence.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>

using namespace vanetza::security;

namespace
{

const std::array<uint8_t, 32> expected_private_key = {
    0x53, 0xb7, 0x7e, 0xb8, 0x48, 0x2e, 0x3c, 0x1a,
    0xd3, 0x36, 0x70, 0xc0, 0xc6, 0xc4, 0x6b, 0xc0,
    0x36, 0x90, 0xd4, 0x00, 0x59, 0xd3, 0xcb, 0xb5,
    0x81, 0xb3, 0x36, 0xaf, 0x8a, 0x98, 0x93, 0xf4
};

const std::array<uint8_t, 32> expected_public_x = {
    0x1c, 0x85, 0x0d, 0xc7, 0x45, 0x63, 0x29, 0x3c,
    0xb0, 0xf3, 0xe5, 0x5e, 0xda, 0x7b, 0x10, 0xec,
    0xb4, 0xe9, 0x74, 0x6f, 0x83, 0x6f, 0x84, 0x76,
    0x96, 0xc3, 0x1e, 0xe8, 0x68, 0x4e, 0x37, 0x76
};

const std::array<uint8_t, 32> expected_public_y = {
    0x28, 0xf1, 0x67, 0xfb, 0x64, 0xce, 0x7b, 0x79,
    0xa6, 0x02, 0x06, 0x2a, 0xac, 0x11, 0x7f, 0x59,
    0x6b, 0xac, 0x77, 0xc7, 0x1c, 0xd6, 0xf4, 0xca,
    0xa7, 0x08, 0x7a, 0xcc, 0xcd, 0xab, 0x91, 0xab
};

void check_key_pair(const ecdsa256::KeyPair& kp)
{
    EXPECT_EQ(kp.private_key.key, expected_private_key);
    EXPECT_EQ(kp.public_key.x, expected_public_x);
    EXPECT_EQ(kp.public_key.y, expected_public_y);
}

ecdsa256::KeyPair make_test_key_pair()
{
    ecdsa256::KeyPair kp;
    kp.private_key.key = expected_private_key;
    kp.public_key.x = expected_public_x;
    kp.public_key.y = expected_public_y;
    return kp;
}

std::string read_file_bytes(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

} // namespace

#if defined VANETZA_WITH_OPENSSL || defined VANETZA_WITH_CRYPTOPP

TEST(Persistence, load_pem)
{
    auto kp = load_private_key_from_pem_file("test_key.pem");
    check_key_pair(kp);
}

TEST(Persistence, load_der)
{
    auto kp = load_private_key_from_der_file("test_key.der");
    check_key_pair(kp);
}

TEST(Persistence, pem_and_der_produce_same_keypair)
{
    auto kp_pem = load_private_key_from_pem_file("test_key.pem");
    auto kp_der = load_private_key_from_der_file("test_key.der");
    EXPECT_EQ(kp_pem.private_key, kp_der.private_key);
    EXPECT_EQ(kp_pem.public_key, kp_der.public_key);
}

TEST(Persistence, v2_load_private_key_from_file)
{
    auto kp = v2::load_private_key_from_file("test_key.der");
    auto kp_ref = load_private_key_from_der_file("test_key.der");
    EXPECT_EQ(kp.private_key, kp_ref.private_key);
    EXPECT_EQ(kp.public_key, kp_ref.public_key);
}

TEST(Persistence, v3_load_private_key_from_file)
{
    auto kp = v3::load_private_key_from_file("test_key.pem");
    auto kp_ref = load_private_key_from_pem_file("test_key.pem");
    EXPECT_EQ(kp.private_key, kp_ref.private_key);
    EXPECT_EQ(kp.public_key, kp_ref.public_key);
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
    auto kp = load_private_key_from_pem_file_openssl("test_key.pem");
    check_key_pair(kp);
}

TEST(Persistence, openssl_load_der)
{
    auto kp = load_private_key_from_der_file_openssl("test_key.der");
    check_key_pair(kp);
}
#endif /* VANETZA_WITH_OPENSSL */

#ifdef VANETZA_WITH_CRYPTOPP
TEST(Persistence, cryptopp_load_pem)
{
    auto kp = load_private_key_from_pem_file_cryptopp("test_key.pem");
    check_key_pair(kp);
}

TEST(Persistence, cryptopp_load_der)
{
    auto kp = load_private_key_from_der_file_cryptopp("test_key.der");
    check_key_pair(kp);
}
#endif /* VANETZA_WITH_CRYPTOPP */

TEST(Persistence, save_and_load_pkcs8_der)
{
    auto kp = make_test_key_pair();
    const std::string path = "test_save.der";
    std::ofstream ofs(path, std::ios::binary);
    EXPECT_TRUE(save_private_key_pkcs8_der(ofs, kp));
    ofs.flush();
    auto loaded = load_private_key_from_der_file(path);
    std::remove(path.c_str());
    check_key_pair(loaded);
}

TEST(Persistence, save_der_matches_reference_file)
{
    auto kp = make_test_key_pair();
    std::ostringstream oss(std::ios::binary);
    EXPECT_TRUE(save_private_key_pkcs8_der(oss, kp));
    auto reference = read_file_bytes("test_key.der");
    EXPECT_EQ(oss.str(), reference);
}
