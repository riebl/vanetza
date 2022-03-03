#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/tests/network_topology.hpp>
#include <vanetza/net/mac_address.hpp>
#include <gtest/gtest.h>
#include <list>
#include <tuple>

using namespace vanetza;
using namespace vanetza::geonet;

// user literal for convenient length definition
vanetza::units::Length operator"" _m(long double length)
{
    return vanetza::units::Length(length * vanetza::units::si::meters);
}

using RoutingParam = std::tuple<NetworkTopology::PacketDuplicationMode, bool>;

class Routing : public ::testing::TestWithParam<RoutingParam>
{
protected:
    virtual void SetUp() override
    {
        net.set_duplication_mode(std::get<0>(GetParam()));
        net.get_mib().itsGnNonAreaForwardingAlgorithm = UnicastForwarding::Greedy;
        net.get_mib().itsGnAreaForwardingAlgorithm = BroadcastForwarding::Advanced;
        net.get_mib().vanetzaCbfMaxCounter = 3;
        net.get_mib().itsGnSecurity = std::get<1>(GetParam());

        cars[0] = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};
        cars[1] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        cars[2] = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06};
        cars[3] = {0x03, 0x02, 0x03, 0x04, 0x05, 0x06};
        cars[4] = {0x04, 0x02, 0x03, 0x04, 0x05, 0x06};
        cars[5] = {0x05, 0x02, 0x03, 0x04, 0x05, 0x06};

        // add all routers
        for (auto& car : cars) {
            net.add_router(car.second);
        }

        // add reachability for all routers
        net.add_reachability(cars[0], {cars[1], cars[2], cars[3], cars[5]});
        net.add_reachability(cars[1], {cars[0], cars[2]});
        net.add_reachability(cars[2], {cars[0], cars[1], cars[3], cars[5]});
        net.add_reachability(cars[3], {cars[0], cars[2], cars[4]});
        net.add_reachability(cars[4], {cars[3]});
        net.add_reachability(cars[5], {cars[2], cars[0]});

        // positioning of cars
        net.set_position(cars[0], CartesianPosition(0.0_m, 0.0_m));
        net.set_position(cars[1], CartesianPosition(2.0_m, 0.0_m));
        net.set_position(cars[2], CartesianPosition(6.0_m, 0.0_m));
        net.set_position(cars[3], CartesianPosition(6.0_m, 4.0_m));
        net.set_position(cars[4], CartesianPosition(20.0_m, 4.0_m));
        net.set_position(cars[5], CartesianPosition(2.0_m, -1.0_m));
        /**
         * [rough map]                (3)                   (4)
         *
         *
         *
         *                  -----
         *              (0)  (1)      (2)
         *                  -----
         *                   (5)
         */

        // advance time so Beacons have been exchanged
        net.advance_time(std::chrono::seconds::zero());
        net.reset_counters();
    }

    std::unique_ptr<DownPacket> create_packet(ByteBuffer&& payload = {47, 11, 1, 4, 42, 85})
    {
        std::unique_ptr<DownPacket> packet { new DownPacket() };
        packet->layer(OsiLayer::Transport) = ByteBuffer(std::move(payload));
        return packet;
    }

    std::unordered_map<int, MacAddress> cars;
    NetworkTopology net;
};

/**
 * Check location table entries after initialisation
 * Expectation: Entries should reflect defined network reachability
 */
TEST_P(Routing, beacon_location_table)
{
    auto& sender_table = net.get_router(cars[0])->get_location_table();
    EXPECT_FALSE(sender_table.has_entry(Address { cars[0] }));
    EXPECT_TRUE(sender_table.has_entry(Address { cars[1] }));
    EXPECT_TRUE(sender_table.has_entry(Address { cars[2] }));
    EXPECT_TRUE(sender_table.has_entry(Address { cars[3] }));
    EXPECT_FALSE(sender_table.has_entry(Address { cars[4] }));
    ASSERT_TRUE(sender_table.has_entry(Address { cars[5] }));
    const LocationTableEntry* entry5 = sender_table.get_entry(Address { cars[5] });
    ASSERT_TRUE(entry5);
    EXPECT_LT(0, entry5->get_position_vector().longitude.value());
    EXPECT_GT(0, entry5->get_position_vector().latitude.value());
}

/**
 * No GN Beacon shall ever be transmitted when beaconing has been disabled explicitly.
 */
TEST_P(Routing, disabled_beaconing)
{
    net.get_mib().vanetzaDisableBeaconing = true;
    net.advance_time(std::chrono::minutes(1));
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    EXPECT_EQ(0, size(net.get_router(cars[0])->get_location_table().neighbours()));
}

/*
 * Preconditions:
 * - source router inside destination area
 * - packet not yet in CBF packet buffer (P not in B)
 * Expectation: immediate broadcast (area forwarding, not greedy forwarding)
 */
TEST_P(Routing, advanced_forwarding_source_inside_destination)
{
    GbcDataRequest gbc_request(net.get_mib());
    gbc_request.destination = circle_dest_area(3.0_m, 2.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(1, net.get_interface(cars[0])->requests);
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
}

/*
 * Preconditions:
 * - receiving router inside destination area (forwarder operations)
 * - packet not yet in CBF packet buffer (P not in B)
 * - LL address of receiver is not LL destination address
 * Expectation: contention based forwarding by receiver
 */
TEST_P(Routing, advanced_forwarding_receiver_inside_destination_cbf)
{
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(5.0_m, 2.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[1])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(1, net.get_interface(cars[1])->requests);
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[1])->last_request.destination);
    net.dispatch();
    // node 1 (source) broadcasted to reachable nodes 0 and 2
    EXPECT_EQ(1, net.get_transport(cars[0])->counter);
    EXPECT_EQ(1, net.get_transport(cars[2])->counter);
    EXPECT_EQ(0, net.get_transport(cars[5])->counter);

    // nodes 0 and 2 have not forwarded anything yet
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    EXPECT_EQ(0, net.get_interface(cars[2])->requests);

    // node 2 forwards first (CBF timer ~99.6ms)
    net.advance_time(std::chrono::microseconds(99650));
    EXPECT_EQ(1, net.get_interface(cars[2])->requests);
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);

    // node 0 forwards second (initial CBF timer ~99.8ms)
    // CBF timer (~99.4ms) of node 0 has been restarted by node 2's forwarding !
    // Note: node 0 is outside sectorial area of node 1 (source) and node 2 (forwarder)
    net.advance_time(std::chrono::microseconds(200));
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    net.advance_time(std::chrono::microseconds(99450));
    EXPECT_EQ(1, net.get_interface(cars[0])->requests);

    // make sure forwarding was to broadcast address
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
    // node 5 received packet twice by now
    EXPECT_EQ(2, net.get_transport(cars[5])->counter);

    // nodes 3 and 4 are outside of destination area
    EXPECT_EQ(0, net.get_transport(cars[3])->counter);
    EXPECT_EQ(0, net.get_transport(cars[4])->counter);
}

/*
 * Preconditions:
 * - source and receiver are inside destination area
 * - source and sender are identical -> receiver is "outside" sectorial area
 * - packet is is addded to CBF packet buffer
 * Expectations:
 * - remove packet from buffer when counter limit is reached
 * - stop timer
 * - discard packet
 */
TEST_P(Routing, advanced_forwarding_max_counter_exceeded)
{
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(2.0_m, 2.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
    net.dispatch();

    auto& car1_cbf = net.get_router(cars[1])->get_cbf_buffer();
    auto found = car1_cbf.find(identifier(Address { cars[0] }, SequenceNumber(0)));
    ASSERT_TRUE(found);
    EXPECT_EQ(1, car1_cbf.counter(identifier(*found)));

    const int max_counter = net.get_mib().vanetzaCbfMaxCounter;
    for (int i = 1; i < max_counter; ++i) {
        // repeat (transmit & dispatch) car0's last link layer transmission
        net.get_interface(cars[0])->transmit();
        net.dispatch();
        auto found = car1_cbf.find(identifier(Address { cars[0] }, SequenceNumber(0)));
        ASSERT_TRUE(found);
        EXPECT_EQ(i + 1, car1_cbf.counter(identifier(*found)));
    }

    // repeat (transmit & dispatch) car0's last link layer transmission
    net.get_interface(cars[0])->transmit();
    net.dispatch();
    found = net.get_router(cars[1])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_FALSE(found);
}

/**
 * Preconditions:
 * - source is outside destination area
 * - receiver is inside destination area
 * Expectations:
 * - receiver adds packet to CBF buffer
 * - receiver forwards packet immediately (received via GF)
 * - receiver does not broadcast packet again after CBF max time
 */
TEST_P(Routing, advanced_forwarding_avoid_double_broadcast)
{
    // greedy forwarding stops at car 1 (optimum) -> broadcast
    auto& car1_cbf = net.get_router(cars[1])->get_cbf_buffer();
    auto& car1_ifc = net.get_interface(cars[1]).get();

    ASSERT_EQ(0, car1_ifc.requests);
    ASSERT_FALSE(car1_cbf.find(identifier(Address { cars[0] }, SequenceNumber(0))));

    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(1.0_m, 2.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    net.dispatch();

    // GBC has been sent by source using greedy forwarding (GF)
    EXPECT_EQ(cars[1], net.get_interface(cars[0])->last_request.destination);

    // receiver has enqueued packet in its CBF buffer
    ASSERT_TRUE(car1_cbf.find(identifier(Address { cars[0] }, SequenceNumber(0))));

    // receiver forwarded packet immediately
    EXPECT_EQ(1, car1_ifc.requests);

    // no further forwarding by receiver
    net.advance_time(units::clock_cast(net.get_mib().itsGnCbfMaxTime));
    EXPECT_FALSE(car1_cbf.find(identifier(Address { cars[0] }, SequenceNumber(0))));
    EXPECT_EQ(1, car1_ifc.requests);
}

/*
 * Preconditions:
 * - source (0), forwarder (5) and receiver (2) inside destination area
 * - distinct source and forwarder spanning sectorial area
 * - receiver inside of sectorial area
 * - packet in CBF packet buffer (P in B)
 * Expectation: remove packet from buffer, stop timer, discard packet
 */
TEST_P(Routing, advanced_forwarding_inside_sectorial_area)
{
    EXPECT_FALSE(net.get_router(cars[5])->outside_sectorial_contention_area(cars[0], cars[2]));

    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(7.0_m, 0.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
    net.dispatch();

    // receiver contends on first packet reception (precondition)
    auto& cbf5 = net.get_router(cars[5])->get_cbf_buffer();
    auto found = cbf5.find(identifier(Address { cars[0] }, SequenceNumber(0)));
    ASSERT_TRUE(found);
    EXPECT_EQ(1, cbf5.counter(identifier(*found)));

    // forwarder's timer expires after ~99.4 ms
    ASSERT_EQ(0, net.get_interface(cars[2])->requests);
    net.advance_time(std::chrono::microseconds(99450));
    EXPECT_EQ(1, net.get_interface(cars[2])->requests);

    // receiver is inside sectorial area and stops contending
    found = net.get_router(cars[5])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_FALSE(found);
}

/*
 * Preconditions:
 * - source (0), forwarder (5) and receiver (2) inside destination area
 * - distinct source and forwarder spanning sectorial area
 * - receiver outside of sectorial area
 * - packet in CBF packet buffer (P in B)
 * Expectation: packet is buffered with incremented counter
 */
TEST_P(Routing, advanced_forwarding_outside_sectorial_area)
{
    net.set_position(cars[5], CartesianPosition(2.0_m, -2.0_m));
    net.advance_time(std::chrono::seconds(5)); /*< let Beacons update location tables */
    net.reset_counters();
    EXPECT_TRUE(net.get_router(cars[5])->outside_sectorial_contention_area(cars[0], cars[2]));

    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(7.0_m, 0.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
    net.dispatch();

    // receiver contends on first packet reception (precondition)
    auto& cbf5 = net.get_router(cars[5])->get_cbf_buffer();
    auto found = cbf5.find(identifier(Address { cars[0] }, SequenceNumber(0)));
    ASSERT_TRUE(found);
    EXPECT_EQ(1, cbf5.counter(identifier(*found)));

    // forwarder's timer expires after ~99.4 ms
    ASSERT_EQ(0, net.get_interface(cars[2])->requests);
    net.advance_time(std::chrono::microseconds(99450));
    EXPECT_EQ(1, net.get_interface(cars[2])->requests);

    // receiver is outside sectorial area and increments counter
    found = cbf5.find(identifier(Address { cars[0] }, SequenceNumber(0)));
    ASSERT_TRUE(found);
    EXPECT_EQ(2, cbf5.counter(identifier(*found)));
}

/*
 * Preconditions:
 * - source (1) is inside destination area
 * - sender (2), forwarder (0), and receiver (5) as well
 *   note: receiver (5) gets packet from (2) for the first time
 * - receiver is in sectorial area of sender (2) and forwarder (0)
 * - sender is different to GBC source
 * Expectation: (5) removes packet from buffer, stops timer, discards packet
 */
TEST_P(Routing, advanced_routing_distinct_sender_sectorial_area)
{
    EXPECT_FALSE(net.get_router(cars[5])->outside_sectorial_contention_area(cars[2], cars[0]));

    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(4.5_m, 2.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[1])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[1])->last_request.destination);
    net.dispatch();

    // sender forwards after ~99.6 ms -> receivers starts contending
    net.advance_time(std::chrono::microseconds(99650));
    EXPECT_EQ(1, net.get_interface(cars[2])->requests);
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    auto found = net.get_router(cars[5])->get_cbf_buffer().find(identifier(Address { cars[1] }, SequenceNumber(0)));
    ASSERT_TRUE(found);
    EXPECT_EQ(1, net.get_router(cars[5])->get_cbf_buffer().counter(identifier(*found)));

    // forwarder's timer expires after ~99.4 ms
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    net.advance_time(std::chrono::microseconds(99450));
    EXPECT_EQ(1, net.get_interface(cars[0])->requests);

    // receiver stopped contending
    found = net.get_router(cars[5])->get_cbf_buffer().find(identifier(Address { cars[1] }, SequenceNumber(0)));
    EXPECT_FALSE(found);
}

/*
 * Preconditions:
 * - source outside target area (non-area forwarding)
 * - source has known neighbours with progress to destination
 * Expectation: unicast greedy forwarding
 */
TEST_P(Routing, greedy_forwarding_unicast)
{
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(1.0_m, 2.0_m, 2.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cars[1], net.get_interface(cars[0])->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0_m, 6.0_m, -2.0_m);
    confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cars[2], net.get_interface(cars[0])->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0_m, 6.0_m, 8.0_m);
    confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cars[3], net.get_interface(cars[0])->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0_m, 2.0_m, 2.0_m);
    confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cars[1], net.get_interface(cars[0])->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0_m, 20.0_m, 0.0_m);
    confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cars[2], net.get_interface(cars[0])->last_request.destination);
}

/*
 * Preconditions:
 * - source outside target area (non-area forwarding)
 * - no known neighbour with progress towards destination
 * - traffic class has SCF disabled
 * Expectation: broadcast
 */
TEST_P(Routing, greedy_forwarding_broadcast)
{
    net.get_mib().itsGnDefaultTrafficClass.store_carry_forward(false);
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    gbc_request.destination = circle_dest_area(1.0_m, -2.0_m, 0.0_m);
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, net.get_interface(cars[0])->last_request.destination);
}

/*
 * Preconditions:
 * - source outside target area (non-area forwarding)
 * - no known neighbour with progress towards destination
 * - traffic class has SCF enabled
 * Expectation: queue packet in broadcast buffer
 */
TEST_P(Routing, greedy_forwarding_scf)
{
    net.get_mib().itsGnDefaultTrafficClass.store_carry_forward(true);
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    gbc_request.destination = circle_dest_area(1.0_m, -2.0_m, 0.0_m);
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);

    // let's age the the lifetime of the buffered packet a little bit
    net.advance_time(units::clock_cast(net.get_mib().itsGnDefaultPacketLifetime.decode() *  0.5));
    net.reset_counters(); /*< ignore Beacon transmissions */

    // move one station to become a forwarder and propagate its new position via SHB
    net.set_position(cars[5], CartesianPosition(-1.0_m, 0.0_m));
    ShbDataRequest shb_request(net.get_mib(), aid::IPV6_ROUTING);
    shb_request.upper_protocol = UpperProtocol::IPv6;
    ASSERT_TRUE(net.get_router(cars[5])->request(shb_request, create_packet()).accepted());

    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    EXPECT_EQ(1, net.get_interface(cars[5])->requests);
    net.dispatch(); /*< dispatches SHB */
    // need to trigger common header processing again
    EXPECT_EQ(0, net.get_interface(cars[0])->requests);
    net.get_router(cars[5])->request(shb_request, create_packet());
    net.dispatch();
    // now SCF buffered packet should be forwarded
    EXPECT_EQ(1, net.get_interface(cars[0])->requests);
    EXPECT_EQ(cars[5], net.get_interface(cars[0])->last_request.destination);
}

/*
 * Preconditions:
 * - receiver outside target area
 * - sender inside target area
 * - position of sender is accurate (PAI)
 * Expectation: receivers located outside discard packet
 */
TEST_P(Routing, forwarding_selection_discard)
{
    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(3.0_m, 0.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    net.dispatch();

    // all four neighbours of car0 received the GBC packet
    EXPECT_EQ(4, net.get_counter_indications());
    // but only 1 and 5 buffer the packet (i.e. they are inside target area)
    auto found1 = net.get_router(cars[1])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_TRUE(found1);
    auto found5 = net.get_router(cars[5])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_TRUE(found5);

    // nodes 2 and 3 have not buffered packet and did no non-area forwarding either
    auto found2 = net.get_router(cars[2])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_FALSE(found2);
    EXPECT_EQ(0, net.get_interface(cars[2])->requests);
    auto found3 = net.get_router(cars[3])->get_cbf_buffer().find(identifier(Address { cars[0] }, SequenceNumber(0)));
    EXPECT_FALSE(found3);
    EXPECT_EQ(0, net.get_interface(cars[3])->requests);
}

/*
 * Preconditions:
 * - receiver outside target area
 * - sender inside target area
 * - position of sender is not accurate (!PAI)
 * Expectation: receivers located outside start area forwarding
 */
TEST_P(Routing, forwarding_selection_inaccurate_position)
{
    net.get_host(cars[0])->set_position_accuracy_indicator(false);
    net.advance_time(std::chrono::seconds(4));
    net.reset_counters();

    GbcDataRequest gbc_request(net.get_mib(), aid::IPV6_ROUTING);
    gbc_request.destination = circle_dest_area(3.0_m, 0.0_m, 0.0_m);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = net.get_router(cars[0])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());
    net.dispatch();

    // all four neighbours of car0 received the GBC packet
    EXPECT_EQ(4, net.get_counter_indications());
    // nodes 2 and 3 start greedy forwarding (they are unsure about sender's position)
    // (greedy forwarding does not care about PAI, so car[0] is a valid selection)
    EXPECT_EQ(1, net.get_interface(cars[2])->requests);
    EXPECT_EQ(cars[0], net.get_interface(cars[2])->last_request.destination);
    EXPECT_EQ(1, net.get_interface(cars[3])->requests);
    EXPECT_EQ(cars[0], net.get_interface(cars[3])->last_request.destination);
}

/*
 * Packet lifetime reported to access layer's request interface
 * shall be reduced by GN forwarders as accurately as possible.
 * Note: The reported lifetime is only as accurate as GN Lifetime field can encode it.
 *       Even in the best case, lifetime is not reduced finer than in 50ms steps.
 */
TEST_P(Routing, forwarding_remaining_lifetime)
{
    GbcDataRequest gbc_request(net.get_mib(), aid::DEN);
    gbc_request.destination = circle_dest_area(18.0_m, 20.0_m, 4.0_m);
    gbc_request.upper_protocol = UpperProtocol::BTP_B;
    gbc_request.maximum_lifetime = Lifetime { Lifetime::Base::One_Second, 3 };
    auto confirm = net.get_router(cars[4])->request(gbc_request, create_packet());
    ASSERT_TRUE(confirm.accepted());

    EXPECT_EQ(std::chrono::seconds(3), net.get_interface(cars[4])->last_request.lifetime);
    EXPECT_EQ(0, net.get_interface(cars[3])->requests);

    net.advance_time(std::chrono::seconds(1));
    EXPECT_EQ(1, net.get_interface(cars[3])->requests);
    auto forwarding_remaining_lifetime = net.get_interface(cars[3])->last_request.lifetime;
    EXPECT_GE(forwarding_remaining_lifetime, std::chrono::milliseconds(2900));
    EXPECT_LT(forwarding_remaining_lifetime, std::chrono::seconds(3));
}

static const auto PacketHandlingValues = ::testing::Combine(
            ::testing::Values(
                NetworkTopology::PacketDuplicationMode::Copy_Construct,
                NetworkTopology::PacketDuplicationMode::Serialize),
            ::testing::Bool());
std::string printPacketHandlingValue(const ::testing::TestParamInfo<Routing::ParamType>& value)
{
    std::string print;
    switch (std::get<0>(value.param)) {
        case NetworkTopology::PacketDuplicationMode::Copy_Construct:
            print = "Copy";
            break;
        case NetworkTopology::PacketDuplicationMode::Serialize:
            print = "Serialize";
            break;
    }
    print += std::get<1>(value.param) ? "WithSecurity" : "WithoutSecurity";
    return print;
}
INSTANTIATE_TEST_SUITE_P(RoutingPacketHandling, Routing, PacketHandlingValues, printPacketHandlingValue);
