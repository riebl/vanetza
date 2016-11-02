#include <gtest/gtest.h>
#include <vanetza/geonet/dcc_mco_field.hpp>

using namespace vanetza::geonet;
using vanetza::dcc::ChannelLoad;

TEST(DccMcoField, ctor)
{
    DccMcoField mco;
    EXPECT_EQ(ChannelLoad(0.0), mco.local_cbr());
    EXPECT_EQ(ChannelLoad(0.0), mco.neighbour_cbr());
    EXPECT_EQ(0, mco.output_power());
}

TEST(DccMcoField, uint32_view)
{
    DccMcoField mco;
    EXPECT_EQ(0, static_cast<uint32_t>(mco));

    // last 11 bits are reserved for future use: masked zero
    mco = DccMcoField(0x12345678);
    EXPECT_EQ(0x12345000, static_cast<uint32_t>(mco));
}

TEST(DccMcoField, channel_load)
{
    DccMcoField mco;
    mco.local_cbr(ChannelLoad(0.5));
    EXPECT_NEAR(0.5, mco.local_cbr().value(), 1.0 / 255.0);

    mco.neighbour_cbr(ChannelLoad(0.25));
    EXPECT_NEAR(0.25, mco.neighbour_cbr().value(), 1.0 / 255.0);
}

TEST(DccMcoField, output_power)
{
    DccMcoField mco;
    mco.output_power(10);
    EXPECT_EQ(10, mco.output_power());

    mco.output_power(31);
    EXPECT_EQ(31, mco.output_power());

    mco.output_power(32);
    EXPECT_EQ(31, mco.output_power());
}
