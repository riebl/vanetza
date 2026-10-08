#include <gtest/gtest.h>
#include <vanetza/common/bit_number.hpp>
#include <cstdint>

using namespace vanetza;

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

TEST(BitNumber, wide_mask) {
    BitNumber<uint32_t, 31> a(0xffffffffu);
    EXPECT_EQ(a.raw(), 0x7fffffffu);

    BitNumber<int32_t, 31> b(-1);
    EXPECT_EQ(b.raw(), 0x7fffffff);

    BitNumber<uint64_t, 32> c(0x123456789aull);
    EXPECT_EQ(c.raw(), 0x3456789aull);

    BitNumber<uint64_t, 40> d(0xff12345678abull);
    EXPECT_EQ(d.raw(), 0x12345678abull);

    BitNumber<int64_t, 63> e(-1);
    EXPECT_EQ(e.raw(), 0x7fffffffffffffffll);
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

