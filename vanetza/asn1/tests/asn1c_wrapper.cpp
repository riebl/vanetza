#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/VanetzaTest.h>

using namespace vanetza::asn1;
typedef vanetza::asn1::asn1c_wrapper<VanetzaTest_t> test_wrapper;
typedef vanetza::asn1::asn1c_oer_wrapper<VanetzaTest_t> test_oer_wrapper;

TEST(asn1c_wrapper, create) {
    EXPECT_NO_THROW({
        test_wrapper wrapper(asn_DEF_VanetzaTest);
    });
}

TEST(asn1c_wrapper, constants) {
    EXPECT_EQ(42, VanetzaTest__field_magicValue);
}

TEST(asn1c_wrapper, size) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "1234");
    EXPECT_EQ(wrapper.size(), 5);
}

TEST(asn1c_wrapper, oer_size) {
    test_oer_wrapper wrapper(asn_DEF_VanetzaTest);
    
    OCTET_STRING_fromString(&wrapper->string, "1234");
    EXPECT_EQ(wrapper.size(), 7);

    OCTET_STRING_fromString(&wrapper->string, "12345");
    EXPECT_EQ(wrapper.size(), 8);
}

TEST(asn1c_wrapper, dereferencing) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    ASSERT_NE(wrapper->field, 3);
    wrapper->field = 3;
    EXPECT_EQ((*wrapper).field, 3);
}

TEST(asn1c_wrapper, copy) {
    test_wrapper wrapper_orig(asn_DEF_VanetzaTest);
    wrapper_orig->field = 5;
    test_wrapper wrapper_copy = wrapper_orig;
    EXPECT_EQ(wrapper_copy->field, 5);
    wrapper_copy->field = 6;
    EXPECT_EQ(wrapper_orig->field, 5);
}

TEST(asn1c_wrapper, self_assignment) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "1234");
    ASSERT_EQ(wrapper.size(), 5);
    test_wrapper& alias = wrapper; // alias hides the intended self-assignment from compiler diagnostics
    wrapper = alias;
    EXPECT_EQ(wrapper.size(), 5);
}

TEST(asn1c_wrapper, validate) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "1234");
    EXPECT_TRUE(wrapper.validate());
    OCTET_STRING_fromString(&wrapper->string, "ABCD"); // non-numerics
    EXPECT_FALSE(wrapper.validate());
    std::string msg;
    EXPECT_FALSE(wrapper.validate(msg));
    EXPECT_FALSE(msg.empty());
}

TEST(asn1c_wrapper, compare) {
    test_wrapper wrapper1(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper1->string, "1234");
    test_wrapper wrapper2(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper2->string, "1234");
    test_wrapper wrapper3(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper3->string, "0123");
    test_wrapper wrapper4(asn_DEF_VanetzaTest);
    wrapper4->field = 5;
    OCTET_STRING_fromString(&wrapper4->string, "1234");

    // .compare()
    EXPECT_EQ(wrapper1.compare(wrapper1), 0);
    EXPECT_EQ(wrapper1.compare(wrapper2), 0);
    EXPECT_EQ(wrapper1.compare(wrapper3), 1);
    EXPECT_EQ(wrapper1.compare(wrapper4), -1);

    // operators == and !=
    EXPECT_TRUE(wrapper1 == wrapper1);
    EXPECT_TRUE(wrapper1 == wrapper2);
    EXPECT_FALSE(wrapper1 == wrapper3);
    EXPECT_TRUE(wrapper1 != wrapper3);
    EXPECT_TRUE(wrapper1 != wrapper4);
}

TEST(asn1c_wrapper, print) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "1234");
    EXPECT_EQ(wrapper.print(), 0);
}

TEST(asn1c_wrapper, encode) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "1234");
    wrapper->field = 8;
    vanetza::ByteBuffer buf = wrapper.encode();
    EXPECT_EQ(wrapper.size(), buf.size());
    // No idea if this is the correct ASN.1 PER equivalent
    EXPECT_EQ(vanetza::ByteBuffer({ 0x04, 0x02, 0x11, 0xA2, 0x80 }), buf);
}

TEST(asn1c_wrapper, decode_valid) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    const vanetza::ByteBuffer buffer { 0x04, 0x02, 0x11, 0xA2, 0x80 };
    bool result = wrapper.decode(buffer);
    ASSERT_TRUE(result);
    EXPECT_EQ(8, wrapper->field);
    ASSERT_EQ(4, wrapper->string.size);
    EXPECT_STREQ("1234", (const char*)(wrapper->string.buf));
}

TEST(asn1c_wrapper, decode_invalid) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    const vanetza::ByteBuffer buffer { 0x12 };
    bool result = wrapper.decode(buffer);
    // should have failed because of short buffer
    ASSERT_FALSE(result);
}

TEST(asn1c_wrapper, decode_range) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    const vanetza::ByteBuffer buffer { 0xC0, 0xFF, 0xEE, 0x04, 0x02, 0x11, 0xA2, 0x80, 0x08, 0x15 };
    auto begin = std::next(buffer.begin(), 3);
    auto end = std::prev(buffer.end(), 2);
    ASSERT_TRUE(wrapper.decode(begin, end));
    EXPECT_EQ(8, wrapper->field);
    EXPECT_EQ(4, wrapper->string.size);
    EXPECT_STREQ("1234", (const char*)(wrapper->string.buf));
}

TEST(asn1c_wrapper, encode_error_reports_failing_type) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "12");
    wrapper->field = 322;
    asn1c_error ec;
    EXPECT_EQ(0u, wrapper.size(ec));
    EXPECT_TRUE(static_cast<bool>(ec));
    EXPECT_EQ(ErrorCode::EncodeFailed, ec.code());
    EXPECT_STREQ("VanetzaTest", ec.root_type_name());
    EXPECT_STREQ("INTEGER", ec.failed_type_name());
    const vanetza::ByteBuffer out = wrapper.encode(ec);
    EXPECT_TRUE(out.empty());
    EXPECT_EQ(ErrorCode::EncodeFailed, ec.code());
}

TEST(asn1c_wrapper, encode_throws_on_constraint_violation) {
    test_wrapper wrapper(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&wrapper->string, "12");
    wrapper->field = 322;
    EXPECT_THROW(wrapper.encode(), asn1c_exception);
}

TEST(asn1c_wrapper, decode_error_maps_result_codes) {
    test_wrapper tx(asn_DEF_VanetzaTest);
    OCTET_STRING_fromString(&tx->string, "12");
    tx->field = 7;
    const vanetza::ByteBuffer buffer = tx.encode();
    ASSERT_GT(buffer.size(), 1u);

    test_wrapper rx(asn_DEF_VanetzaTest);
    asn1c_error ec;
    rx.decode(buffer, ec);
    EXPECT_FALSE(static_cast<bool>(ec));

    asn1c_error ec_trunc;
    rx.decode(vanetza::ByteBuffer(buffer.begin(), buffer.begin() + 1), ec_trunc);
    EXPECT_EQ(ErrorCode::DecodeIncomplete, ec_trunc.code());

    asn1c_error ec_empty;
    rx.decode(vanetza::ByteBuffer {}, ec_empty);
    EXPECT_EQ(ErrorCode::DecodeIncomplete, ec_empty.code());

    asn1c_error ec_bad;
    rx.decode(vanetza::ByteBuffer(4, 0xFF), ec_bad);
    EXPECT_EQ(ErrorCode::DecodeFailed, ec_bad.code());
}
