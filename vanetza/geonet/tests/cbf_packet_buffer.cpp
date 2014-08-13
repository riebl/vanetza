#include <gtest/gtest.h>
#include <vanetza/geonet/cbf_packet_buffer.hpp>
#include <vanetza/geonet/mib.hpp>

using namespace vanetza;
using namespace vanetza::geonet;
using units::si::seconds;

class CbfPacketBufferTest : public ::testing::Test
{
protected:
    CbfPacket create_packet();
    CbfPacket create_packet(std::size_t length);

    const MIB mib;
    Timestamp now;
};

CbfPacket CbfPacketBufferTest::create_packet()
{
    CbfPacket::PduPtr pdu { new CbfPacket::PduPtr::element_type(mib) };
    CbfPacket::PayloadPtr payload { new CbfPacket::PayloadPtr::element_type() };

    return CbfPacket(std::move(pdu), std::move(payload));
}

CbfPacket CbfPacketBufferTest::create_packet(std::size_t size)
{
    auto packet = create_packet();
    assert(packet.pdu);
    assert(packet.pdu->length() <= size);
    const std::size_t payload = size - packet.pdu->length();
    packet.payload->operator[](OsiLayer::Application) = ByteBuffer(payload);
    assert(length(packet) == size);
    return packet;
}


TEST_F(CbfPacketBufferTest, packet_length)
{
    CbfPacket packet = create_packet();
    EXPECT_EQ(packet.pdu->length(), length(packet));

    packet.payload->operator[](OsiLayer::Application) = ByteBuffer(30);
    EXPECT_EQ(packet.pdu->length() + 30, length(packet));

    packet.pdu.reset();
    EXPECT_EQ(30, length(packet));

    packet.payload.reset();
    EXPECT_EQ(0, length(packet));
}

TEST_F(CbfPacketBufferTest, next_timer_expiry)
{
    CbfPacketBuffer buffer(8192);
    EXPECT_FALSE(!!buffer.next_timer_expiry());

    buffer.push(create_packet(), 3.0 * seconds, now);
    ASSERT_TRUE(!!buffer.next_timer_expiry());
    EXPECT_EQ(now + Timestamp::duration_type(3.0 * seconds), buffer.next_timer_expiry().get());

    now += Timestamp::duration_type(1.0 * seconds);
    buffer.push(create_packet(), 1.0 * seconds, now);
    ASSERT_TRUE(!!buffer.next_timer_expiry());
    EXPECT_EQ(now + Timestamp::duration_type(1.0 * seconds), buffer.next_timer_expiry().get());
}

TEST_F(CbfPacketBufferTest, try_drop_sequence_number)
{
    CbfPacketBuffer buffer(8192);
    const auto mac = MacAddress {1, 1, 1, 1, 1, 1};
    EXPECT_FALSE(buffer.try_drop(mac, SequenceNumber(3)));

    auto packet = create_packet();
    packet.pdu->extended().source_position.gn_addr.mid(mac);
    packet.pdu->extended().sequence_number = SequenceNumber(8);
    buffer.push(std::move(packet), 0.4 * seconds, now);
    EXPECT_FALSE(buffer.try_drop(mac, SequenceNumber(7)));
    EXPECT_FALSE(buffer.try_drop(mac, SequenceNumber(9)));
    EXPECT_TRUE(buffer.try_drop(mac, SequenceNumber(8)));
    EXPECT_FALSE(buffer.try_drop(mac, SequenceNumber(8)));
}

TEST_F(CbfPacketBufferTest, try_drop_mac)
{
    CbfPacketBuffer buffer(8192);
    const auto mac1 = MacAddress {1, 1, 1, 1, 1, 1};
    const auto mac2 = MacAddress {2, 2, 2, 2, 2, 2};

    auto packet = create_packet();
    packet.pdu->extended().source_position.gn_addr.mid(mac1);
    packet.pdu->extended().sequence_number = SequenceNumber(8);
    buffer.push(std::move(packet), 0.4 * seconds, now);
    EXPECT_FALSE(buffer.try_drop(mac2, SequenceNumber(8)));
    EXPECT_TRUE(buffer.try_drop(mac1, SequenceNumber(8)));
}

TEST_F(CbfPacketBufferTest, try_drop_multiple_packets)
{
    CbfPacketBuffer buffer(8192);
    const auto mac = MacAddress {1, 1, 1, 1, 1, 1};

    auto packet1 = create_packet();
    packet1.pdu->extended().source_position.gn_addr.mid(mac);
    packet1.pdu->extended().sequence_number = SequenceNumber(8);
    buffer.push(std::move(packet1), 0.4 * seconds, now);

    auto packet2 = create_packet();
    packet2.pdu->extended().source_position.gn_addr.mid(mac);
    packet2.pdu->extended().sequence_number = SequenceNumber(10);
    buffer.push(std::move(packet2), 0.4 * seconds, now);

    EXPECT_FALSE(buffer.try_drop(mac, SequenceNumber(9)));
    EXPECT_TRUE(buffer.try_drop(mac, SequenceNumber(10)));
    EXPECT_TRUE(buffer.try_drop(mac, SequenceNumber(8)));
}

TEST_F(CbfPacketBufferTest, capacity)
{
    CbfPacketBuffer buffer(256);

    buffer.push(create_packet(128), 0.5 * seconds, now);
    buffer.push(create_packet(128), 0.5 * seconds, now);
    now += Timestamp::duration_type(0.55 * seconds);
    EXPECT_EQ(2, buffer.packets_to_send(now).size());

    buffer.push(create_packet(157), 0.5 * seconds, now);
    buffer.push(create_packet(100), 0.5 * seconds, now);
    now += Timestamp::duration_type(1.0 * seconds);
    auto packets = buffer.packets_to_send(now);
    ASSERT_EQ(1, packets.size());
    EXPECT_EQ(100, length(packets.front()));
}

TEST_F(CbfPacketBufferTest, packets_to_send)
{
    CbfPacketBuffer buffer(8192);
    auto packets = buffer.packets_to_send(now);
    EXPECT_EQ(0, packets.size());

    now += Timestamp::duration_type(1.0 * seconds);
    buffer.push(create_packet(), 3.0 * seconds, now);
    packets = buffer.packets_to_send(now);
    EXPECT_EQ(0, packets.size());

    buffer.push(create_packet(), 5.0 * seconds, now);
    now += Timestamp::duration_type(3.0 * seconds);
    packets = buffer.packets_to_send(now);
    EXPECT_EQ(1, packets.size());

    now += Timestamp::duration_type(3.0 * seconds);
    packets = buffer.packets_to_send(now);
    EXPECT_EQ(1, packets.size());

    buffer.push(create_packet(), 1.0 * seconds, now);
    buffer.push(create_packet(), 1.5 * seconds, now);
    now += Timestamp::duration_type(2.0 * seconds);
    packets = buffer.packets_to_send(now);
    ASSERT_EQ(2, packets.size());
}
