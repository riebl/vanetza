#include <vanetza/security/persistence/certificate.hpp>
#include <vanetza/security/persistence/tests/temporary_file.hpp>
#include <vanetza/security/tests/certificates_v3.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <gtest/gtest.h>
#include <filesystem>
#include <system_error>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::persistence;

namespace
{

v3::Certificate authorization_ticket()
{
    // NIST P-256 generator, FIPS 186-4 D.1.2.3
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::Y1;
    key.x = security::buffer_from_hexstring("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    return v3::make_authorization_ticket(key, Clock::at("2026-11-14 12:00"));
}

} // namespace

class CertificateFileTest : public TemporaryFileTest
{
};

TEST_F(CertificateFileTest, save_v3_writes_oer_encoding)
{
    EXPECT_FALSE(save_certificate(path, authorization_ticket()));
    EXPECT_EQ(authorization_ticket().encode(), read());
}

TEST_F(CertificateFileTest, load_v3_reads_oer_encoding)
{
    write(authorization_ticket().encode());
    const expected<v3::Certificate> loaded = load_v3_certificate(path);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
    EXPECT_EQ(authorization_ticket().encode(), loaded->encode());
}

TEST_F(CertificateFileTest, loading_v3_from_missing_file_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, load_v3_certificate(path).error());
}

TEST_F(CertificateFileTest, loading_v3_from_truncated_file_is_illegal_byte_sequence)
{
    ByteBuffer truncated = authorization_ticket().encode();
    truncated.pop_back();
    write(truncated);
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_v3_certificate(path).error());
}

TEST_F(CertificateFileTest, saving_v3_failing_encoding_is_invalid_argument)
{
    // issuer identifier lacks its choice
    EXPECT_EQ(std::errc::invalid_argument, save_certificate(path, v3::Certificate {}));
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(CertificateFileTest, saving_v3_into_missing_directory_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, save_certificate(missing_path, authorization_ticket()));
}
