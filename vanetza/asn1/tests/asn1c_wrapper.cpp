#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include "gen/Test.h"

using namespace vanetza::asn1;
typedef vanetza::asn1::asn1c_wrapper<Test_t> test_wrapper;

TEST(asn1c_wrapper, create) {
    EXPECT_NO_THROW({
        test_wrapper wrapper(asn_DEF_Test);
    });
}

TEST(asn1c_wrapper, size) {
    test_wrapper wrapper(asn_DEF_Test);
    EXPECT_EQ(wrapper.size(), 2);
}

TEST(asn1c_wrapper, dereferencing) {
    test_wrapper wrapper(asn_DEF_Test);
    ASSERT_NE(wrapper->field, 3);
    wrapper->field = 3;
    EXPECT_EQ((*wrapper).field, 3);
}

TEST(asn1c_wrapper, copy) {
    test_wrapper wrapper_orig(asn_DEF_Test);
    wrapper_orig->field = 5;
    test_wrapper wrapper_copy = wrapper_orig;
    EXPECT_EQ(wrapper_copy->field, 5);
    wrapper_copy->field = 6;
    EXPECT_EQ(wrapper_orig->field, 5);
}

TEST(asn1c_wrapper, validate) {
    test_wrapper wrapper(asn_DEF_Test);
    EXPECT_TRUE(wrapper.validate());
    wrapper->field = 832; // out of range
    EXPECT_FALSE(wrapper.validate());
    std::string msg;
    EXPECT_FALSE(wrapper.validate(msg));
    EXPECT_FALSE(msg.empty());
}

TEST(asn1c_wrapper, encode) {
    test_wrapper wrapper(asn_DEF_Test);
    wrapper->field = 0xde;
    vanetza::ByteBuffer buf = wrapper.encode();
    EXPECT_EQ(wrapper.size(), buf.size());
    // TODO: not completely sure if 0x6f is correct
    // However, 0x6f contains 0xde bit pattern
    EXPECT_EQ(vanetza::ByteBuffer({ 0x6f, 0x00 }), buf);
}

TEST(asn1c_wrapper, decode_valid) {
    test_wrapper wrapper(asn_DEF_Test);
    const vanetza::ByteBuffer buffer { 0x6f, 0x00 };
    bool result = wrapper.decode(buffer);
    ASSERT_TRUE(result);
    EXPECT_EQ(0xde, wrapper->field);
}

TEST(asn1c_wrapper, decode_invalid) {
    test_wrapper wrapper(asn_DEF_Test);
    const vanetza::ByteBuffer buffer { 0x12 };
    bool result = wrapper.decode(buffer);
    // should have failed because of short buffer
    ASSERT_FALSE(result);
}
