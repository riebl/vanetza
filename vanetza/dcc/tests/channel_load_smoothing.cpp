#include <gtest/gtest.h>
#include <vanetza/dcc/channel_load_smoothing.hpp>

using namespace vanetza::dcc;

TEST(ChannelLoadSmoothing, update) {
    ChannelLoadSmoothing smoother;
    EXPECT_EQ(ChannelLoad(0.0), smoother.channel_load());

    smoother.update(ChannelLoad(0.5));
    EXPECT_EQ(ChannelLoad(0.25), smoother.channel_load());

    smoother.update(ChannelLoad(1.0));
    EXPECT_EQ(ChannelLoad(0.625), smoother.channel_load());

    smoother.update(ChannelLoad(0.0));
    EXPECT_EQ(ChannelLoad(0.3125), smoother.channel_load());

    smoother.update(ChannelLoad(0.0));
    EXPECT_EQ(ChannelLoad(0.15625), smoother.channel_load());
}
