#include <vanetza/geonet/gbc_memory.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/tests/network_topology.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::geonet;

vanetza::units::Length operator"" _m(long double length)
{
    return vanetza::units::Length(length * vanetza::units::si::meters);
}

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

TEST(GbcMemory, network)
{
    NetworkTopology net;
    net.get_mib().vanetzaGbcMemoryCapacity = 10;
    net.get_mib().vanetzaDisableBeaconing = true;
    net.get_mib().vanetzaFadingCbfCounter = true;
    net.set_network_delay(std::chrono::milliseconds(4));

    MacAddress car1 = create_mac_address(1);
    net.add_router(car1);
    net.set_position(car1, CartesianPosition(0.0_m, 0.0_m));

    MacAddress car2 = create_mac_address(2);
    net.add_router(car2);
    net.set_position(car2, CartesianPosition(0.0_m, 100.0_m));

    MacAddress car3 = create_mac_address(3);
    net.add_router(car3);
    net.set_position(car3, CartesianPosition(0.0_m, 50.0_m));

    MacAddress car4 = create_mac_address(4);
    net.add_router(car4);
    net.set_position(car4, CartesianPosition(0.0_m, -75.0_m));

    net.build_fully_meshed_reachability();
    EXPECT_EQ(0, net.get_interface(car1)->transmissions);
    EXPECT_EQ(0, net.get_transport(car2)->counter);

    GbcDataRequest gbc_request(net.get_mib());
    gbc_request.destination = circle_dest_area(150.0_m, 0.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    std::unique_ptr<DownPacket> gbc_payload { new DownPacket() };
    gbc_payload->layer(OsiLayer::Transport) = ByteBuffer(42);
    auto gbc_confirm = net.get_router(car1)->request(gbc_request, std::move(gbc_payload));
    ASSERT_TRUE(gbc_confirm.accepted());

    net.advance_time(std::chrono::milliseconds(5));
    EXPECT_EQ(1, net.get_interface(car1)->transmissions);
    EXPECT_EQ(1, net.get_transport(car2)->counter);

    // spend some time for packet forwarding operations
    net.advance_time(std::chrono::seconds(1));
    // explicitly repeat the last transmission of car1 without delay
    //net.set_network_delay(std::chrono::seconds(0));
    net.get_interface(car1)->transmit();
    net.dispatch();
    // no duplicate passed to transport layer
    EXPECT_EQ(1, net.get_transport(car2)->counter);
    // though more packets have been transmitted on link layer
    EXPECT_LE(2, net.get_interface(car1)->transmissions);
}
