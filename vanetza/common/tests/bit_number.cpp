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

