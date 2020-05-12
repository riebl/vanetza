#include <vanetza/geonet/gbc_memory.hpp>
#include <gtest/gtest.h>

using namespace vanetza::geonet;

static GbcMemory::PacketIdentifier make_identifier(int station, std::uint16_t sn)
{
    Address addr;
    addr.mid(vanetza::create_mac_address(station));
    return std::make_tuple(addr, SequenceNumber {sn});
}

TEST(GbcMemory, size)
{
    GbcMemory mem;
    EXPECT_EQ(0, mem.size());

    mem.remember(make_identifier(1, 1));
    EXPECT_EQ(1, mem.size());

    mem.capacity(3);
    EXPECT_EQ(1, mem.size());

    mem.remember(make_identifier(1, 1));
    EXPECT_EQ(1, mem.size());

    mem.remember(make_identifier(1, 2));
    mem.remember(make_identifier(1, 1));
    EXPECT_EQ(2, mem.size());

    mem.remember(make_identifier(1, 3));
    mem.remember(make_identifier(1, 4));
    EXPECT_EQ(3, mem.size());
}

TEST(GbcMemory, capacity)
{
    GbcMemory mem;
    mem.capacity(8);

    for (int i = 0; i < 10; ++i) {
        mem.remember(make_identifier(1, i));
    }
    EXPECT_EQ(8, mem.size());

    mem.capacity(2);
    EXPECT_EQ(2, mem.size());

    EXPECT_FALSE(mem.knows(make_identifier(1, 7)));
    EXPECT_TRUE(mem.knows(make_identifier(1, 8)));
    EXPECT_TRUE(mem.knows(make_identifier(1, 9)));
}

TEST(GbcMemory, knows)
{
    GbcMemory mem;
    mem.capacity(3);

    EXPECT_FALSE(mem.knows(make_identifier(2, 8)));
    EXPECT_FALSE(mem.remember(make_identifier(2, 8)));
    EXPECT_TRUE(mem.knows(make_identifier(2, 8)));
}

TEST(GbcMemory, remember)
{
    GbcMemory mem;
    mem.capacity(2);

    EXPECT_FALSE(mem.remember(make_identifier(2, 8)));
    EXPECT_TRUE(mem.remember(make_identifier(2, 8)));
    EXPECT_FALSE(mem.remember(make_identifier(12, 25)));
    EXPECT_FALSE(mem.remember(make_identifier(2, 5)));
    EXPECT_EQ(2, mem.size());
    EXPECT_FALSE(mem.knows(make_identifier(2, 8)));
}
