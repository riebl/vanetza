#include <gtest/gtest.h>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/cbf_counter.hpp>
#include <vanetza/geonet/cbf_packet_buffer.hpp>
#include <vanetza/geonet/mib.hpp>
#include <functional>

using namespace std::chrono;
using namespace vanetza;
using namespace vanetza::geonet;

static const size_t GbcPduLength = BasicHeader::length_bytes +
    CommonHeader::length_bytes + GeoBroadcastHeader::length_bytes;

class CbfPacketBufferTest : public ::testing::Test
{
protected:
    using PduPtr = std::unique_ptr<GbcPdu>;
    using PayloadPtr = std::unique_ptr<DownPacket>;
    using PendingPacketCbf = PendingPacket<GbcPdu>;

    void SetUp() override
    {
        // lifetime of 3 seconds can be stored with 50 ms accuracy
        mib.itsGnDefaultPacketLifetime.encode(3.0 * units::si::seconds);
        runtime.reset(Clock::time_point { hours(42) });
        calls = 0;
        last_call_length = 0;
    }

    CbfPacket create_packet(const MacAddress&, SequenceNumber::value_type, std::size_t length = GbcPduLength) const;
    CbfPacket create_packet(std::size_t length = GbcPduLength) const;
    CbfPacketBuffer::TimerCallback callback();
    std::unique_ptr<CbfCounter> counter();

    MIB mib;
    ManualRuntime runtime;
    unsigned calls;
    unsigned last_call_length;
};

CbfPacket CbfPacketBufferTest::create_packet(const MacAddress& mac, SequenceNumber::value_type sn, std::size_t size) const
{
    PduPtr pdu { new CbfPacketBufferTest::PduPtr::element_type(mib) };
    pdu->extended().source_position.gn_addr.mid(mac);
    pdu->extended().sequence_number = SequenceNumber { sn };
    PayloadPtr payload { new CbfPacketBufferTest::PayloadPtr::element_type() };
    assert(get_length(*pdu) <= size);

    const std::size_t payload_size = size - get_length(*pdu);
    payload->layer(OsiLayer::Application) = ByteBuffer(payload_size);

    PendingPacketCbf pending { std::make_tuple(std::move(pdu), std::move(payload)), [](PendingPacketCbf::Packet&&) {} };
    return CbfPacket(std::move(pending), cBroadcastMacAddress);
}

CbfPacket CbfPacketBufferTest::create_packet(std::size_t length) const
{
    static unsigned counter = 0;
    return create_packet({0, 0, 0, 0, 0, 0}, ++counter, length);
}

CbfPacketBuffer::TimerCallback CbfPacketBufferTest::callback()
{
    return [this](PendingPacketCbf&& data) {
        ++calls;
        last_call_length = data.length();
    };
}

std::unique_ptr<CbfCounter> CbfPacketBufferTest::counter()
{
    return std::unique_ptr<CbfCounter> { new CbfCounterImmortal() };
}


TEST_F(CbfPacketBufferTest, identifier_hash)
{
    std::hash<CbfPacketIdentifier> hasher;
    CbfPacketIdentifier id1 { Address {{ 1, 2, 3, 4, 5, 6}}, SequenceNumber(2) };
    CbfPacketIdentifier id2 { Address {{ 1, 2, 3, 4, 5, 6}}, SequenceNumber(3) };
    CbfPacketIdentifier id3 { Address {{ 1, 2, 3, 4, 5, 6}}, SequenceNumber(2) };
    CbfPacketIdentifier id4 { Address {{ 1, 2, 3, 4, 5, 7}}, SequenceNumber(3) };
    EXPECT_EQ(id1, id3);
    EXPECT_EQ(hasher(id1), hasher(id3));
    EXPECT_NE(id1, id2);
    EXPECT_NE(hasher(id1), hasher(id2));
    EXPECT_NE(id2, id4);
    EXPECT_NE(hasher(id2), hasher(id4));
}

TEST_F(CbfPacketBufferTest, packet_identifier)
{
    const MacAddress mac { 1, 3, 5, 7, 9, 11 };
    CbfPacket packet = create_packet(mac, 8);
    EXPECT_EQ(mac, packet.source().mid());
    EXPECT_EQ(SequenceNumber { 8 }, packet.sequence_number());
}


TEST_F(CbfPacketBufferTest, packet_lifetime)
{
    CbfPacket packet = create_packet({}, 1);

    // check initialization
    using vanetza::units::clock_cast;
    EXPECT_EQ(clock_cast(mib.itsGnDefaultPacketLifetime.decode()), packet.reduce_lifetime(Clock::duration::zero()));

    // lifetime has to be modifiable
    Clock::duration lifetime = packet.reduce_lifetime(Clock::duration::zero());
    EXPECT_EQ(lifetime - milliseconds(50), packet.reduce_lifetime(milliseconds(50)));
    // but negative reductions have no effect
    EXPECT_EQ(lifetime - milliseconds(50), packet.reduce_lifetime(milliseconds(-100)));
    // and lifetime does not go below zero
    EXPECT_EQ(Clock::duration::zero(), packet.reduce_lifetime(milliseconds(6000)));
}

TEST_F(CbfPacketBufferTest, packet_length)
{
    CbfPacket packet1 = create_packet({0, 1, 2, 3, 4, 5}, 3);
    EXPECT_EQ(GbcPduLength, packet1.length());

    CbfPacket packet2 = create_packet({0, 1, 2, 3, 4, 5}, 3, 64);
    EXPECT_EQ(64, packet2.length());
}

TEST_F(CbfPacketBufferTest, find)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    auto found1 = buffer.find(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(3)));
    EXPECT_FALSE(found1);

    auto packet1 = create_packet({1, 2, 3, 4, 5, 6}, 3);
    buffer.add(std::move(packet1), seconds(5));

    auto found2 = buffer.find(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(4)));
    EXPECT_FALSE(found2);
    auto found3 = buffer.find(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(3)));
    ASSERT_TRUE(found3);
    EXPECT_EQ(1, buffer.counter(identifier(*found3)));
    EXPECT_EQ((MacAddress {1, 2, 3, 4, 5, 6}), found3->source().mid());
}

TEST_F(CbfPacketBufferTest, counter)
{
    CbfPacket packet1 = create_packet({3, 8, 3, 8, 3, 8}, 10);
    CbfPacketIdentifier id1 = identifier(packet1);
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    EXPECT_EQ(0, buffer.counter(id1));

    buffer.add(std::move(packet1), milliseconds(30));
    EXPECT_EQ(1, buffer.counter(id1));

    buffer.remove(id1);
    EXPECT_EQ(1, buffer.counter(id1));

    CbfPacket packet2 = create_packet({3, 8, 3, 8, 3, 8}, 11);
    CbfPacketIdentifier id2 = identifier(packet2);
    buffer.update(id2, milliseconds(30));
    EXPECT_EQ(0, buffer.counter(id2));

    buffer.add(std::move(packet2), milliseconds(30));
    EXPECT_EQ(1, buffer.counter(id2));

    buffer.update(id2, milliseconds(30));
    EXPECT_EQ(2, buffer.counter(id2));

    EXPECT_EQ(1, buffer.counter(id1));
}

TEST_F(CbfPacketBufferTest, fetch)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    auto found1 = buffer.fetch(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(3)));
    EXPECT_FALSE(!!found1);

    auto packet1 = create_packet({1, 2, 3, 4, 5, 6}, 3);
    buffer.add(std::move(packet1), milliseconds(500));

    auto found2 = buffer.fetch(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(4)));
    EXPECT_FALSE(!!found2);
    auto found3 = buffer.fetch(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(3)));
    ASSERT_TRUE(!!found3);
    EXPECT_EQ((MacAddress {1, 2, 3, 4, 5, 6}), found3->source().mid());

    auto found4 = buffer.fetch(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(3)));
    EXPECT_FALSE(!!found4);
}

TEST_F(CbfPacketBufferTest, fetch_reduce_lifetime)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    auto packet = create_packet({1, 2, 3, 4, 5, 6}, 1);
    buffer.add(std::move(packet), milliseconds(500));
    runtime.trigger(milliseconds(200));
    auto found = buffer.fetch(identifier(Address {{1, 2, 3, 4, 5, 6}}, SequenceNumber(1)));
    ASSERT_TRUE(!!found);
    EXPECT_EQ(milliseconds(2800), found->reduce_lifetime(Clock::duration::zero()));
}

TEST_F(CbfPacketBufferTest, next_timer_expiry)
{
    const Address addr {{1, 2, 3, 4, 5, 6}};

    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    EXPECT_EQ(Clock::time_point::max(), runtime.next());

    buffer.add(create_packet(), seconds(3));
    EXPECT_EQ(seconds(3), runtime.next() - runtime.now());

    runtime.trigger(seconds(1));
    buffer.add(create_packet(addr.mid(), 3), seconds(1));
    EXPECT_EQ(seconds(1), runtime.next() - runtime.now());

    buffer.add(create_packet(addr.mid(), 2), milliseconds(200));
    EXPECT_EQ(milliseconds(200), runtime.next() - runtime.now());

    runtime.trigger(milliseconds(100));
    auto fetch = buffer.fetch(identifier(addr, SequenceNumber(2)));
    EXPECT_TRUE(!!fetch);
    EXPECT_EQ(milliseconds(900), runtime.next() - runtime.now());

    bool dropped = buffer.remove(identifier(addr, SequenceNumber(3)));
    EXPECT_TRUE(dropped);
    EXPECT_EQ(milliseconds(1900), runtime.next() - runtime.now());
}

TEST_F(CbfPacketBufferTest, remove_sequence_number)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    const auto addr = Address {{1, 1, 1, 1, 1, 1}};
    EXPECT_FALSE(buffer.remove(identifier(addr, SequenceNumber(3))));

    auto packet = create_packet(addr.mid(), 8);
    buffer.add(std::move(packet), milliseconds(400));
    EXPECT_FALSE(buffer.remove(identifier(addr, SequenceNumber(7))));
    EXPECT_FALSE(buffer.remove(identifier(addr, SequenceNumber(9))));
    EXPECT_TRUE(buffer.remove(identifier(addr, SequenceNumber(8))));
    EXPECT_FALSE(buffer.remove(identifier(addr, SequenceNumber(8))));
}

TEST_F(CbfPacketBufferTest, remove_drop_addr)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    const auto addr1 = Address {{1, 1, 1, 1, 1, 1}};
    const auto addr2 = Address {{ 2, 2, 2, 2, 2, 2}};

    auto packet = create_packet(addr1.mid(), 8);
    buffer.add(std::move(packet), milliseconds(400));
    EXPECT_FALSE(buffer.remove(identifier(addr2, SequenceNumber(8))));
    EXPECT_TRUE(buffer.remove(identifier(addr1, SequenceNumber(8))));
    EXPECT_FALSE(buffer.remove(identifier(addr1, SequenceNumber(8))));
}

TEST_F(CbfPacketBufferTest, remove_multiple_packets)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 8192);
    const auto addr = Address {{1, 1, 1, 1, 1, 1}};
    const auto timeout = milliseconds(400);

    auto packet1 = create_packet(addr.mid(), 8);
    buffer.add(std::move(packet1), timeout);

    auto packet2 = create_packet(addr.mid(), 10);
    buffer.add(std::move(packet2), timeout);

    EXPECT_FALSE(buffer.remove(identifier(addr, SequenceNumber(9))));
    EXPECT_TRUE(buffer.remove(identifier(addr, SequenceNumber(10))));
    EXPECT_TRUE(buffer.remove(identifier(addr, SequenceNumber(8))));
}

TEST_F(CbfPacketBufferTest, capacity)
{
    CbfPacketBuffer buffer(runtime, callback(), counter(), 256);

    buffer.add(create_packet(128), seconds(1));
    buffer.add(create_packet(128), seconds(1));
    runtime.trigger(milliseconds(1010));
    EXPECT_EQ(2, calls);

    buffer.add(create_packet(157), seconds(1));
    buffer.add(create_packet(100), seconds(1));
    runtime.trigger(seconds(2));
    EXPECT_EQ(3, calls);
    EXPECT_EQ(100, last_call_length);
}

TEST_F(CbfPacketBufferTest, packets_to_send)
{
    std::vector<PendingPacketCbf> packets;
    auto cb = [&packets](PendingPacketCbf&& data) { packets.emplace_back(std::move(data)); };
    CbfPacketBuffer buffer(runtime, cb, counter(), 8192);

    runtime.trigger(minutes(42));
    EXPECT_EQ(0, packets.size());

    buffer.add(create_packet(110), milliseconds(2500));
    runtime.trigger(seconds(1));
    EXPECT_EQ(0, packets.size());

    buffer.add(create_packet(120), seconds(1));
    runtime.trigger(seconds(1));
    ASSERT_EQ(1, packets.size());
    EXPECT_EQ(120, packets[0].length());

    runtime.trigger(milliseconds(500));
    EXPECT_EQ(2, packets.size());

    buffer.add(create_packet(130), seconds(1));
    buffer.add(create_packet(140), milliseconds(1500));
    runtime.trigger(seconds(2));
    ASSERT_EQ(4, packets.size());
    EXPECT_EQ(130, packets[2].length());
    EXPECT_EQ(140, packets[3].length());

    // check if lifetime is reduced by queuing time
    auto packet = create_packet(150);

    EXPECT_EQ(milliseconds(1000), packet.reduce_lifetime(milliseconds(2000)));
    buffer.add(std::move(packet), milliseconds(72));
    runtime.trigger(runtime.next());
    ASSERT_EQ(5, packets.size());
    // Lifetime can only be encoded in 50ms steps (in best case): 950 ms remaining lifetime
    EXPECT_EQ((Lifetime {Lifetime::Base::Fifty_Milliseconds, 19}), packets[4].pdu().basic().lifetime);
}
