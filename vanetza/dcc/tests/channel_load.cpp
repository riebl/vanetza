#include <gtest/gtest.h>
#include <vanetza/dcc/channel_load.hpp>

using namespace vanetza::dcc;

TEST(ChannelLoad, ctor)
{
    ChannelLoad cl1;
    EXPECT_DOUBLE_EQ(0.0, cl1.value());

    ChannelLoad cl2(30, 250);
    EXPECT_DOUBLE_EQ(0.12, cl2.value());

    ChannelLoad cl3(0, 0);
    EXPECT_DOUBLE_EQ(0.0, cl3.value());
}

TEST(ChannelLoadRational, less)
{
    EXPECT_LT(ChannelLoad(30, 100), ChannelLoad(31, 100));
    EXPECT_LT(ChannelLoad(30, 100), ChannelLoad(8, 25));
    EXPECT_LT(ChannelLoad(0,10), ChannelLoad(1, 2));
}
