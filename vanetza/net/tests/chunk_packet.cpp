#include <gtest/gtest.h>
#include <vanetza/net/chunk_packet.hpp>

using vanetza::ByteBuffer;
using vanetza::ChunkPacket;
using vanetza::OsiLayer;

TEST(ChunkPacket, ctor)
{
    ChunkPacket packet;
    EXPECT_EQ(0, packet.size());
}

TEST(ChunkPacket, size_from_to)
{
    ChunkPacket packet;
    packet[OsiLayer::Link] = ByteBuffer(8);
    packet[OsiLayer::Session] = ByteBuffer(19);
    packet[OsiLayer::Application] = ByteBuffer(5);

    EXPECT_EQ(8, packet.size(OsiLayer::Link, OsiLayer::Link));
    EXPECT_EQ(0, packet.size(OsiLayer::Network, OsiLayer::Transport));
    EXPECT_EQ(27, packet.size(OsiLayer::Physical, OsiLayer::Session));
    EXPECT_EQ(24, packet.size(OsiLayer::Session, OsiLayer::Application));
}

TEST(ChunkPacket, access)
{
    const ByteBuffer data { 3, 8, 7, 5, 6 };
    ChunkPacket packet;
    packet[OsiLayer::Transport] = ByteBuffer { data };

    EXPECT_EQ(data.size(), packet.size());
    EXPECT_EQ(data.size(), packet[OsiLayer::Transport].size());

    ByteBuffer tmp;
    packet[OsiLayer::Transport].convert(tmp);
    EXPECT_EQ(data, tmp);
}

TEST(ChunkPacket, copy)
{
    ChunkPacket original;
    original[OsiLayer::Physical] = ByteBuffer(12);
    original[OsiLayer::Presentation] = ByteBuffer(34);

    ChunkPacket copy { original };
    EXPECT_EQ(46, copy.size());
    EXPECT_EQ(12, copy[OsiLayer::Physical].size());
    EXPECT_EQ(34, copy[OsiLayer::Presentation].size());

    ChunkPacket tmp;
    tmp = original;
    EXPECT_EQ(46, tmp.size());
}
