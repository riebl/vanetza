#include <gtest/gtest.h>
#include <vanetza/common/bit_number.hpp>
#include <cstdint>

using namespace vanetza;

TEST(BitNumber, wide_mask) {
    constexpr auto unsigned_mask = BitNumber<uint64_t, 63>::mask;
    constexpr auto signed_mask = BitNumber<int64_t, 63>::mask;
    EXPECT_EQ(unsigned_mask, UINT64_C(0x7fffffffffffffff));
    EXPECT_EQ(signed_mask, INT64_C(0x7fffffffffffffff));
    BitNumber<uint64_t, 40> value(UINT64_MAX);
    EXPECT_EQ(value.raw(), UINT64_C(0xffffffffff));
}

TEST(BitNumber, zero_width_bool) {
    BitNumber<bool, 0> value(true);
    EXPECT_FALSE(value.raw());
}

TEST(BitNumber, ctor) {
    BitNumber<uint32_t, 20> a;
    EXPECT_EQ(a.raw(), 0);

    BitNumber<uint32_t, 20> b(0x0fffff);
    EXPECT_EQ(b.raw(), 0x0fffff);
}

TEST(BitNumber, mask) {
    BitNumber<uint32_t, 20> a(0xf01234);
    EXPECT_EQ(a.raw(), 0x1234);

    BitNumber<uint32_t, 1> b(4);
    EXPECT_EQ(b.raw(), 0);
    b = 1;
    EXPECT_EQ(b.raw(), 1);
}

TEST(BitNumber, equality) {
    BitNumber<int8_t, 3> a;
    BitNumber<int8_t, 3> b(0);
    EXPECT_EQ(a, b);

    a = 3;
    EXPECT_NE(a, b);
}

TEST(BitNumber, less) {
    BitNumber<uint16_t, 4> a(3);
    BitNumber<uint16_t, 4> b(4);
    EXPECT_LT(a, b);
    EXPECT_LE(a, b);
    EXPECT_GT(b, a);

    a = 4;
    EXPECT_LE(a, b);
    EXPECT_GE(a, b);

    b = 17; // 17 is masked to 1
    EXPECT_LE(b, a);
}

