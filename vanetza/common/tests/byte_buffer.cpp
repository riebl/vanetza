#include <gtest/gtest.h>
#include <vanetza/common/byte_buffer.hpp>

using namespace vanetza;

struct A
{
    char b[10];
};

TEST(ByteBuffer, buffer_cast) {
    ByteBuffer buf = { 'A', ' ', 't', 'e', 's', 't', ' ', 'b', 'u', 'f', 'f', 'e', 'r' };
    ASSERT_GE(buf.size(), sizeof(A));
    A* a = buffer_cast<A>(buf);
    ASSERT_NE(nullptr, a);
    EXPECT_EQ(a->b[0], 'A');
    EXPECT_EQ(a->b[4], 's');
    EXPECT_EQ(a->b[9], 'f');
}

