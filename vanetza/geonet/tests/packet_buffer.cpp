#include <gtest/gtest.h>
#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/packet_buffer.hpp>
#include <vanetza/geonet/shb_header.hpp>
#include <chrono>

using std::chrono::seconds;
using std::chrono::milliseconds;
using namespace vanetza;
using namespace vanetza::geonet;

struct FakePacket
{
    FakePacket(unsigned id) : id(id) {}

    const unsigned id = 0;
    std::size_t length = 0;
    Clock::duration lifetime = Clock::duration::zero();
};

class FakeData : public packet_buffer::Data
{
public:
    FakeData(unsigned id, std::list<FakePacket>& flushed) : m_flushed(flushed), m_packet(id) {}
    FakePacket& packet() { return m_packet; }

    std::size_t length() const override { return m_packet.length; }
    Clock::duration reduce_lifetime(Clock::duration d) override { m_packet.lifetime -= d; return m_packet.lifetime; }
    void flush() override { m_flushed.push_back(m_packet); }

private:
    std::list<FakePacket>& m_flushed;
    FakePacket m_packet;
};

class PacketBufferTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        counter = 0;
        now = Clock::time_point { std::chrono::minutes(1234) };
    }

    std::unique_ptr<FakeData> create_valid_length(std::size_t length)
    {
        std::unique_ptr<FakeData> data { new FakeData(++counter, flushed) };
        data->packet().length = length;
        return data;
    }

    std::unique_ptr<FakeData> create_valid_lifetime(Clock::duration d)
    {
        std::unique_ptr<FakeData> data { new FakeData(++counter, flushed) };
        data->packet().length = 100;
        data->packet().lifetime = d;
        return data;
    }

    Clock::time_point now;
    unsigned counter;
    std::list<FakePacket> flushed;
};



TEST_F(PacketBufferTest, push)
{
    PacketBuffer buffer(8192);
    EXPECT_TRUE(buffer.push(create_valid_length(5000), now));
    EXPECT_TRUE(buffer.push(create_valid_length(5000), now));
    EXPECT_FALSE(buffer.push(create_valid_length(8200), now));
}

TEST_F(PacketBufferTest, flush_head_drop)
{
    PacketBuffer buffer(8192);
    buffer.push(create_valid_length(2000), now);
    buffer.push(create_valid_length(3000), now);
    buffer.push(create_valid_length(4000), now);

    EXPECT_EQ(0, flushed.size());
    buffer.flush(now);
    ASSERT_EQ(2, flushed.size());
    EXPECT_EQ(2, flushed.front().id);
    EXPECT_EQ(3, flushed.back().id);

    // buffer shall be empty now (flushed list remains empty)
    flushed.clear();
    buffer.flush(now);
    EXPECT_EQ(0, flushed.size());
}

TEST_F(PacketBufferTest, flush_expired)
{
    PacketBuffer buffer(8192);
    buffer.push(create_valid_lifetime(milliseconds(3200)), now);
    now += seconds(3);
    buffer.push(create_valid_lifetime(milliseconds(10300)), now);
    buffer.push(create_valid_lifetime(seconds(1)), now);

    now += seconds(2);
    buffer.flush(now);
    ASSERT_EQ(1, flushed.size());
    EXPECT_EQ(2, flushed.front().id);
}

TEST_F(PacketBufferTest, update_lifetime)
{
    PacketBuffer buffer(8192);
    buffer.push(create_valid_lifetime(milliseconds(2300)), now);
    now += milliseconds(150);
    buffer.flush(now);
    ASSERT_EQ(1, flushed.size());
    EXPECT_EQ(milliseconds(2150), flushed.front().lifetime);
}
