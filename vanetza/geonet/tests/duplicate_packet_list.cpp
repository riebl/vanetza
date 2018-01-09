#include <gtest/gtest.h>
#include <vanetza/geonet/duplicate_packet_list.hpp>

using namespace vanetza::geonet;

TEST(DuplicatePacketList, check)
{
    DuplicatePacketList dpl(3);
    EXPECT_FALSE(dpl.check(SequenceNumber { 30 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 30 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 31 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 30 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 29 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 29 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 30 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 36 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 31 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 30 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 31 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 36 }));
}

TEST(DuplicatePacketList, counter)
{
    DuplicatePacketList dpl(3);
    EXPECT_EQ(0, dpl.counter(SequenceNumber { 8 }));
    EXPECT_FALSE(dpl.check(SequenceNumber { 8 }));
    EXPECT_EQ(1, dpl.counter(SequenceNumber { 8 }));
    EXPECT_TRUE(dpl.check(SequenceNumber { 8 }));
    EXPECT_EQ(2, dpl.counter(SequenceNumber { 8 }));

    EXPECT_FALSE(dpl.check(SequenceNumber { 1 }));
    EXPECT_EQ(1, dpl.counter(SequenceNumber { 1 }));
    EXPECT_EQ(2, dpl.counter(SequenceNumber { 8} ));
}
