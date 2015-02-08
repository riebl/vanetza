#include <vanetza/security/int_x.hpp>
#include <vanetza/security/length_coding.hpp>
#include <gtest/gtest.h>

using vanetza::ByteBuffer;
using vanetza::security::IntX;

TEST(IntX, set_and_get) {
    IntX a;
    EXPECT_EQ(0, a.get<int>());
    EXPECT_EQ(0, a.get<uint16_t>());

    a.set(static_cast<int8_t>(89));
    EXPECT_EQ(89, a.get<int8_t>());
    EXPECT_EQ(89, a.get<uint32_t>());

    a.set(static_cast<uint32_t>(0x12345678));
    EXPECT_EQ(0x12345678, a.get<uint32_t>());
    EXPECT_DEATH(a.get<uint16_t>(), "");
}

TEST(IntX, size) {
    IntX a;
    EXPECT_EQ(0, a.size());

    a.set(static_cast<int8_t>(89));
    EXPECT_EQ(1, a.size());

    a.set(static_cast<uint32_t>(0x00330033));
    EXPECT_EQ(3, a.size());

    a.set(static_cast<uint32_t>(0x33003300));
    EXPECT_EQ(4, a.size());

    a.set(0);
    EXPECT_EQ(0, a.size());
}

TEST(IntX, encode) {
    IntX a;
    EXPECT_EQ((ByteBuffer { 0x00 }), a.encode());

    a.set(127);
    EXPECT_EQ((ByteBuffer { 127 }), a.encode());

    a.set(128);
    EXPECT_EQ((ByteBuffer { 0x80, 128 }), a.encode());

    a.set(0x00120034);
    EXPECT_EQ((ByteBuffer { 0xd2, 0x00, 0x34 }), a.encode());

    a.set(0x00320034);
    EXPECT_EQ((ByteBuffer { 0xe0, 0x32, 0x00, 0x34 }), a.encode());
}

TEST(IntX, decode) {
    ByteBuffer buf { 0xe0, 0x32, 0x00, 0x34 };
    auto decoded = IntX::decode(buf);
    ASSERT_TRUE(!!decoded);
    EXPECT_EQ(0x320034, decoded->get());
}

