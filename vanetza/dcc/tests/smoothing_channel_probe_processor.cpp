#include <gtest/gtest.h>
#include <vanetza/dcc/smoothing_channel_probe_processor.hpp>

using namespace vanetza::dcc;

TEST(SmoothingChannelProbeProcessor, smoothing) {
    SmoothingChannelProbeProcessor cpp;
    EXPECT_EQ(ChannelLoad(0.0), cpp.channel_load());

    cpp.indicate(ChannelLoad(0.5));
    EXPECT_EQ(ChannelLoad(0.25), cpp.channel_load());

    cpp.indicate(ChannelLoad(1.0));
    EXPECT_EQ(ChannelLoad(0.625), cpp.channel_load());

    cpp.indicate(ChannelLoad(0.0));
    EXPECT_EQ(ChannelLoad(0.3125), cpp.channel_load());

    cpp.indicate(ChannelLoad(0.0));
    EXPECT_EQ(ChannelLoad(0.15625), cpp.channel_load());
}

TEST(SmoothingChannelProbeProcessor, update_call) {
    ChannelLoad tmp;
    SmoothingChannelProbeProcessor cpp;
    cpp.on_indication = [&tmp](ChannelLoad cl) { tmp = cl; };

    cpp.indicate(ChannelLoad(0.5));
    EXPECT_EQ(ChannelLoad(0.25), tmp);
}
