#include <gtest/gtest.h>
#include <vanetza/dcc/channel_load.hpp>

using namespace vanetza::dcc;

TEST(ChannelLoadRational, ctor)
{
    ChannelLoadRational cl1;
    EXPECT_EQ(0, cl1.probes_above);
    EXPECT_EQ(0, cl1.probes_total);

    ChannelLoadRational cl2(30, 250);
    EXPECT_EQ(30, cl2.probes_above);
    EXPECT_EQ(250, cl2.probes_total);
}

 TEST(ChannelLoadRational, less)
{
    EXPECT_LT(ChannelLoadRational(30, 100), ChannelLoadRational(31, 100));
    EXPECT_LT(ChannelLoadRational(30, 100), ChannelLoadRational(8, 25));
    EXPECT_LT(ChannelLoadRational(0,10), ChannelLoadRational(1, 2));
}
