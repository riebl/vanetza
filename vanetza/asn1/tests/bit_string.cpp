#include <gtest/gtest.h>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/bit_string.hpp>

using namespace vanetza::asn1;

TEST(bit_string, allocate_twelve_bits) {
    auto bits = make_unique<BIT_STRING_t>(asn_DEF_BIT_STRING);
    allocate_bits(*bits, 12);

    EXPECT_EQ(2u, bits->size);
    EXPECT_EQ(4, bits->bits_unused);
    ASSERT_NE(nullptr, bits->buf);
    EXPECT_EQ(0, bits->buf[0]);
    EXPECT_EQ(0, bits->buf[1]);
}

TEST(bit_string, allocate_sixteen_bits) {
    auto bits = make_unique<BIT_STRING_t>(asn_DEF_BIT_STRING);
    allocate_bits(*bits, 16);

    EXPECT_EQ(2u, bits->size);
    EXPECT_EQ(0, bits->bits_unused);
}

TEST(bit_string, allocate_single_bit) {
    auto bits = make_unique<BIT_STRING_t>(asn_DEF_BIT_STRING);
    allocate_bits(*bits, 1);

    EXPECT_EQ(1u, bits->size);
    EXPECT_EQ(7, bits->bits_unused);
}

TEST(bit_string, set_bit) {
    auto bits = make_unique<BIT_STRING_t>(asn_DEF_BIT_STRING);
    allocate_bits(*bits, 12);

    set_bit(*bits, 0);
    set_bit(*bits, 9);

    EXPECT_EQ(0x80, bits->buf[0]);
    EXPECT_EQ(0x40, bits->buf[1]);
}
