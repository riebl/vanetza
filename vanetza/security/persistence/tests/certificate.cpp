#include <vanetza/common/serialization_buffer.hpp>
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

// authorization ticket of FOKUS WebValidator
const char v2_ticket_hex[] =
    "02015388DEC640C6E19E010052000004B27D4D442F58E065F8D500478929BC843940F3C34D46C547"
    "5803C03594E35BD7E0132FD01634E86D4F50F7F2366988E12525232D00D03E98FC21CA8E5D0AF370"
    "02E0210B24030100002504010000000B0114E9DB83154CBC0203000000553C8D2B8A4E53F3D84A88"
    "37BEEBE83D5C7F68484AC5EFCEEFCC7B0BC5E9531754AAF58BF90790A10F2FD11796A85E13DFFAAC"
    "6073D2068465DA733994CD0C71";

v2::Certificate v2_ticket()
{
    v2::Certificate certificate;
    security::deserialize_from_hexstring(v2_ticket_hex, certificate);
    return certificate;
}

ByteBuffer serialized(const v2::Certificate& certificate)
{
    ByteBuffer buffer;
    serialize_into_buffer(certificate, buffer);
    return buffer;
}

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

TEST_F(CertificateFileTest, save_v2_writes_serialization)
{
    EXPECT_FALSE(save_certificate(path, v2_ticket()));
    EXPECT_EQ(security::buffer_from_hexstring(v2_ticket_hex), read());
}

TEST_F(CertificateFileTest, load_v2_reads_serialization)
{
    write(security::buffer_from_hexstring(v2_ticket_hex));
    const expected<v2::Certificate> loaded = load_v2_certificate(path);
    ASSERT_TRUE(loaded.has_value()) << loaded.error().message();
    EXPECT_EQ(security::buffer_from_hexstring(v2_ticket_hex), serialized(*loaded));
}

TEST_F(CertificateFileTest, loading_v2_from_missing_file_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, load_v2_certificate(path).error());
}

TEST_F(CertificateFileTest, loading_v2_from_truncated_file_is_illegal_byte_sequence)
{
    ByteBuffer truncated = security::buffer_from_hexstring(v2_ticket_hex);
    truncated.pop_back();
    write(truncated);
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_v2_certificate(path).error());
}

TEST_F(CertificateFileTest, loading_v2_from_v3_file_is_illegal_byte_sequence)
{
    write(authorization_ticket().encode());
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_v2_certificate(path).error());
}

TEST_F(CertificateFileTest, loading_v2_with_undecodable_length_is_illegal_byte_sequence)
{
    // validity restrictions (length 11) replaced by a length exceeding 64 bit, decoding continues at signature
    const std::size_t validity_restrictions = 95;
    ByteBuffer malformed = security::buffer_from_hexstring(v2_ticket_hex);
    ASSERT_EQ(11, malformed.at(validity_restrictions));
    malformed.erase(malformed.begin() + validity_restrictions, malformed.begin() + validity_restrictions + 1 + 11);
    malformed.insert(malformed.begin() + validity_restrictions, 9, 0xFF);
    write(malformed);
    EXPECT_EQ(std::errc::illegal_byte_sequence, load_v2_certificate(path).error());
}

TEST_F(CertificateFileTest, saving_v2_failing_serialization_is_invalid_argument)
{
    v2::Certificate certificate = v2_ticket();
    certificate.subject_attributes.push_back(EccPoint { X_Coordinate_Only {} });
    EXPECT_EQ(std::errc::invalid_argument, save_certificate(path, certificate));
    EXPECT_FALSE(std::filesystem::exists(path));
}

TEST_F(CertificateFileTest, saving_v2_into_missing_directory_is_no_such_file)
{
    EXPECT_EQ(std::errc::no_such_file_or_directory, save_certificate(missing_path, v2_ticket()));
}

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
