#include <vanetza/security/persistence/public_key.hpp>
#include <vanetza/security/persistence/tests/temporary_file.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <system_error>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::persistence;

namespace
{

// NIST P-256 generator, FIPS 186-4 D.1.2.3
PublicKey nist_p256_generator()
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::NoCompression;
    key.x = security::buffer_from_hexstring("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    key.y = security::buffer_from_hexstring("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return key;
}

// SubjectPublicKeyInfo of nist_p256_generator, accepted as EC public key by OpenSSL 3.5 "pkey -pubin"
const ByteBuffer generator_der = security::buffer_from_hexstring(
    "3059301306072A8648CE3D020106082A8648CE3D03010703420004"
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

const std::string generator_pem =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n"
    "6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n"
    "-----END PUBLIC KEY-----\n";

void expect_generator(const expected<PublicKey>& key)
{
    ASSERT_TRUE(key.has_value()) << key.error().message();
    EXPECT_EQ(KeyType::NistP256, key->type);
    EXPECT_EQ(KeyCompression::NoCompression, key->compression);
    EXPECT_EQ(nist_p256_generator().x, key->x);
    EXPECT_EQ(nist_p256_generator().y, key->y);
}

} // namespace

class PublicKeyFileTest : public TemporaryFileTest
{
};

TEST_F(PublicKeyFileTest, save_pem_writes_subject_public_key_info)
{
    EXPECT_FALSE(save_public_key_pem(path, nist_p256_generator()));
    const ByteBuffer content = read();
    EXPECT_EQ(generator_pem, std::string(content.begin(), content.end()));
}

TEST_F(PublicKeyFileTest, save_der_writes_subject_public_key_info)
{
    EXPECT_FALSE(save_public_key_der(path, nist_p256_generator()));
    EXPECT_EQ(generator_der, read());
}

TEST_F(PublicKeyFileTest, load_pem_reads_subject_public_key_info)
{
    write(generator_pem);
    expect_generator(load_public_key_pem(path));
}

TEST_F(PublicKeyFileTest, load_der_reads_subject_public_key_info)
{
    write(generator_der);
    expect_generator(load_public_key_der(path));
}

TEST_F(PublicKeyFileTest, loading_missing_file_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, load_public_key_pem(path).error());
    EXPECT_EQ(std::errc::no_such_file_or_directory, load_public_key_der(path).error());
}

TEST_F(PublicKeyFileTest, loading_malformed_content_is_illegal_byte_sequence)
{
    write("-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n");
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_public_key_pem(path).error());
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_public_key_der(path).error());
}

TEST_F(PublicKeyFileTest, saving_malformed_key_is_invalid_argument)
{
    PublicKey malformed = nist_p256_generator();
    malformed.type = KeyType::Unspecified;
    EXPECT_EQ(std::errc::invalid_argument, save_public_key_pem(path, malformed));
    EXPECT_EQ(std::errc::invalid_argument, save_public_key_der(path, malformed));
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(PublicKeyFileTest, saving_into_missing_directory_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, save_public_key_pem(missing_path, nist_p256_generator()));
    EXPECT_EQ(std::errc::no_such_file_or_directory, save_public_key_der(missing_path, nist_p256_generator()));
}
