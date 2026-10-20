#include <vanetza/asn1/asn1c_error.hpp>
#include <vanetza/asn1/its/DescriptiveName.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace vanetza::asn1;

TEST(Asn1cError, default_is_ok) {
    asn1c_error ec;
    EXPECT_FALSE(static_cast<bool>(ec));
    EXPECT_EQ(ErrorCode::Ok, ec.code());
    EXPECT_STREQ("", ec.root_type_name());
    EXPECT_STREQ("", ec.failed_type_name());
}

TEST(Asn1cError, carries_code_and_types) {
    asn1c_error ec(ErrorCode::EncodeFailed, &asn_DEF_DescriptiveName, &asn_DEF_DescriptiveName);
    EXPECT_TRUE(static_cast<bool>(ec));
    EXPECT_EQ(ErrorCode::EncodeFailed, ec.code());
    EXPECT_STREQ("DescriptiveName", ec.root_type_name());
    EXPECT_STREQ("DescriptiveName", ec.failed_type_name());
}

TEST(Asn1cError, exception_is_a_runtime_error) {
    asn1c_error ec(ErrorCode::EncodeFailed, &asn_DEF_DescriptiveName, &asn_DEF_DescriptiveName);
    try {
        throw asn1c_exception(ec);
    } catch (const std::runtime_error& e) {
        EXPECT_STRNE("", e.what());
    }
    EXPECT_EQ(ErrorCode::EncodeFailed, asn1c_exception(ec).code());
}
