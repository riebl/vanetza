#include <gtest/gtest.h>
#include <vanetza/security/peer_request_tracker.hpp>

using namespace vanetza::security;

HashedId3 create_id(uint32_t id)
{
    HashedId3 hid;
    hid[0] = id & 0xFF;
    hid[1] = (id >> 8) & 0xFF;
    hid[2] = (id >> 16) & 0xFF;
    return hid;
}

TEST(PeerRequestTracker, is_pending)
{
    PeerRequestTracker tracker;
    EXPECT_FALSE(tracker.is_pending(create_id(42)));
    tracker.add_request(create_id(42));
    EXPECT_TRUE(tracker.is_pending(create_id(42)));
    tracker.discard_request(create_id(42));
    EXPECT_FALSE(tracker.is_pending(create_id(42)));
}

TEST(PeerRequestTracker, bounded_capacity)
{
    PeerRequestTracker tracker(2);
    tracker.add_request(create_id(1));
    tracker.add_request(create_id(2));
    EXPECT_TRUE(tracker.is_pending(create_id(1)));
    EXPECT_TRUE(tracker.is_pending(create_id(2)));

    tracker.add_request(create_id(3));
    EXPECT_TRUE(tracker.is_pending(create_id(3)));
    EXPECT_TRUE(tracker.is_pending(create_id(2)));
    // dropped oldest pending request
    EXPECT_FALSE(tracker.is_pending(create_id(1)));
}

TEST(PeerRequestTracker, keep_order)
{
    PeerRequestTracker tracker(4);
    tracker.add_request(create_id(1));
    tracker.add_request(create_id(2));
    tracker.add_request(create_id(3));
    tracker.add_request(create_id(4));
    tracker.add_request(create_id(3));
    tracker.add_request(create_id(2));

    std::list<HashedId3> expected = { create_id(1), create_id(2), create_id(3), create_id(4) };
    EXPECT_EQ(expected, tracker.all());

    // nothing left in tracker
    EXPECT_FALSE(tracker.next_one().has_value());
}

TEST(PeerRequestTracker, next_one)
{
    PeerRequestTracker tracker(3);
    tracker.add_request(create_id(0xc0));
    tracker.add_request(create_id(0xff));
    tracker.add_request(create_id(0xee));
    tracker.add_request(create_id(0x42));

    EXPECT_EQ(tracker.next_one(), create_id(0xff));
    EXPECT_EQ(tracker.next_one(), create_id(0xee));
    EXPECT_EQ(tracker.next_one(), create_id(0x42));
    EXPECT_FALSE(tracker.next_one());
}

TEST(PeerRequestTracker, next_n)
{
    PeerRequestTracker tracker(6);
    tracker.add_request(create_id(0x01));
    tracker.add_request(create_id(0x02));
    tracker.add_request(create_id(0x03));
    tracker.add_request(create_id(0x04));
    tracker.add_request(create_id(0x05));

    std::list<HashedId3> expected = { create_id(0x01), create_id(0x02), create_id(0x03) };
    EXPECT_EQ(expected, tracker.next_n(3));

    expected = { create_id(0x04), create_id(0x05) };
    EXPECT_EQ(expected, tracker.next_n(8));

    expected = { };
    EXPECT_EQ(expected, tracker.next_n(2));
}