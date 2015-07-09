#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/tests/network_topology.hpp>
#include <vanetza/net/mac_address.hpp>
#include <gtest/gtest.h>
#include <list>

using namespace vanetza;
using namespace vanetza::geonet;
using namespace vanetza::units::si;

class Routing: public ::testing::Test {
protected:
    Routing() {}

    virtual void SetUp() {
        addy_car1 = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        addy_car2 = {0x02, 0x02, 0x03, 0x04, 0x05, 0x06};
        addy_car3 = {0x03, 0x02, 0x03, 0x04, 0x05, 0x06};
        addy_car4 = {0x04, 0x02, 0x03, 0x04, 0x05, 0x06};
        addy_car5 = {0x05, 0x02, 0x03, 0x04, 0x05, 0x06};
        addy_sender = {0x00, 0x02, 0x03, 0x04, 0x05, 0x06};

        // add all routers
        test.add_router(addy_sender);
        test.add_router(addy_car1);
        test.add_router(addy_car2);
        test.add_router(addy_car3);
        test.add_router(addy_car4);
        test.add_router(addy_car5);

        // add reachability for all routers
        test.add_reachability(addy_sender, std::list<MacAddress> {addy_car1, addy_car2, addy_car3, addy_car5});
        test.add_reachability(addy_car1, std::list<MacAddress> {addy_sender, addy_car2});
        test.add_reachability(addy_car2, std::list<MacAddress> {addy_sender, addy_car1, addy_car3, addy_car5});
        test.add_reachability(addy_car3, std::list<MacAddress> {addy_sender, addy_car2, addy_car4});
        test.add_reachability(addy_car4, std::list<MacAddress> {addy_car3});
        test.add_reachability(addy_car5, std::list<MacAddress> {addy_car2, addy_sender});

        // positioning of cars
        test.set_position(addy_sender, CartesianPosition(0.0 * meter, 0.0 * meter));
        test.set_position(addy_car1, CartesianPosition(2.0 * meter, 0.0 * meter));
        test.set_position(addy_car2, CartesianPosition(6.0 * meter, 0.0 * meter));
        test.set_position(addy_car3, CartesianPosition(6.0 * meter, 6.0 * meter));
        test.set_position(addy_car4, CartesianPosition(20.0 * meter, 6.0 * meter));
        test.set_position(addy_car5, CartesianPosition(2.0 * meter, -1.0 * meter));

        // create Packet
        packet_down = std::unique_ptr<DownPacket>{ new DownPacket() };
        packet_down->layer(OsiLayer::Transport) = ByteBuffer(send_payload);

        // advance time 5 seconds
        test.advance_time(5000 * Timestamp::millisecond);
        test.reset_counters();
    }

    MacAddress addy_car1;
    MacAddress addy_car2;
    MacAddress addy_car3;
    MacAddress addy_car4;
    MacAddress addy_car5;
    MacAddress addy_sender;
    std::unique_ptr<DownPacket> packet_down;
    const ByteBuffer send_payload { 47, 11, 1, 4, 42, 85 };
    NetworkTopology test;
};

TEST_F(Routing, advanced_forwarding_in_destarea_unbuffered_lladdrIsDest) {
/* Test-Scenario
 * GeoAdhocRouter inside target area (INOUT1>=0 true)
 * Packet not yet in CBF packet buffer (P in B false)
 * LL address of GeoAdhoc Router is LL destination address (Dest_LL_ADDR=L_LL_ADDR true)
 * --> greedy forwarding */
    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 2.0, 0.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_sender)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car1, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 6.0, 0.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car2, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 6.0, 6.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car3, test.get_interface(addy_sender)->last_request.destination);
}

TEST_F(Routing, advanced_forwarding_in_destarea_unbuffered_lladdrIsNotDest) {
/* Test-Scenario
 * GeoAdhocRouter inside target area (INOUT1>=0 true)
 * Packet not yet in CBF packet buffer (P in B false)
 * LL address of GeoAdhoc Router is not LL destination address (Dest_LL_ADDR=L_LL_ADDR false)
 * --> contention based forwarding */
    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(10.0, 0.0, 0.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    test.get_interface(addy_sender)->last_packet.reset();
    EXPECT_FALSE(!!test.get_interface(addy_sender)->last_packet);
    auto confirm = test.get_router(addy_sender)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());

    test.advance_time(100 * Timestamp::millisecond);
    EXPECT_TRUE(!!test.get_interface(addy_sender)->last_packet);
    EXPECT_EQ(cBroadcastMacAddress, test.get_interface(addy_sender)->last_request.destination);
}

TEST_F(Routing, advanced_forwarding_in_destarea_buffered_maxCounter) {
/* Test-Scenario
 * GeoAdhocRouter inside target area (INOUT1>=0 true)
 * Packet in CBF packet buffer (P in B true)
 * Counter >= max.Counter is true
 * --> remove packet from buffer, stop timer, discard packet, return -1 */
    const int maxCounter = 3;

    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 2.0, 0.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_sender)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car1, test.get_interface(addy_sender)->last_request.destination);
    test.dispatch();
    auto found = test.get_router(addy_car1)->get_cbf_buffer().find(addy_sender, SequenceNumber(0));
    EXPECT_TRUE(!!found);
    EXPECT_EQ(1, found->counter());

    for (int i = 0; i < maxCounter - 1; i++) {
        test.send(addy_sender, addy_car1);
        EXPECT_EQ(i+2, found->counter());
    }

    test.send(addy_sender, addy_car1);
    found = test.get_router(addy_car1)->get_cbf_buffer().find(addy_sender, SequenceNumber(0));
    EXPECT_FALSE(!!found);
}

TEST_F(Routing, advanced_forwarding_in_destarea_buffered_notMaxCounter_inSectorial) {
/* Test-Scenario
 * GeoAdhocRouter inside target area (INOUT1>=0 true)
 * Packet in CBF packet buffer (P in B true)
 * Counter >= max.Counter is false
 * GeoAdhocRouter is inside sectorial area (INOUT2>=0 true)
 * --> remove packet from buffer, stop timer, discard packet, return -1 */
    EXPECT_FALSE(test.get_router(addy_car5)->outside_sectorial_contention_area(addy_sender, addy_car2));

    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 2.0, -1.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_car2)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car5, test.get_interface(addy_car2)->last_request.destination);
    test.dispatch();
    auto found = test.get_router(addy_car5)->get_cbf_buffer().find(addy_car2, SequenceNumber(0));
    EXPECT_TRUE(!!found);
    EXPECT_EQ(1, found->counter());

    test.get_interface(addy_sender)->last_packet = decltype(test.get_interface(addy_sender)->last_packet)
        (new ChunkPacket(*test.get_interface(addy_car2)->last_packet));
    test.send(addy_sender, addy_car5);
    found = test.get_router(addy_car5)->get_cbf_buffer().find(addy_car2, SequenceNumber(0));
    EXPECT_FALSE(!!found);
}

TEST_F(Routing, advanced_forwarding_in_destarea_buffered_notMaxCounter_outsideSectorial) {
/* Test-Scenario
 * GeoAdhocRouter inside target area (INOUT1>=0 true)
 * Packet in CBF packet buffer (P in B true)
 * Counter >= max.Counter is false
 * GeoAdhocRouter is outside sectorial area (INOUT2>=0 true)
 * --> packet is buffered (counter++, start timer (TO_CBF_GBC), return 0) */
    test.set_position(addy_car5, CartesianPosition(20.0 * meter, -1.0 * meter));
    test.advance_time(5000 * Timestamp::millisecond);
    EXPECT_TRUE(test.get_router(addy_car5)->outside_sectorial_contention_area(addy_sender, addy_car2));

    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 20.0, -1.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_car2)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car5, test.get_interface(addy_car2)->last_request.destination);
    test.dispatch();
    auto found = test.get_router(addy_car5)->get_cbf_buffer().find(addy_car2, SequenceNumber(0));
    EXPECT_TRUE(!!found);
    EXPECT_EQ(1, found->counter());

    test.get_interface(addy_sender)->last_packet = decltype(test.get_interface(addy_sender)->last_packet)
        (new ChunkPacket(*test.get_interface(addy_car2)->last_packet));
    test.send(addy_sender, addy_car5);
    found = test.get_router(addy_car5)->get_cbf_buffer().find(addy_car2, SequenceNumber(0));
    EXPECT_TRUE(!!found);
    EXPECT_EQ(2, found->counter());
}

TEST_F(Routing, advanced_forwarding_out_destarea_sender_out_destarea) {
/* Test-Scenario
 * GeoAdhocRouter outside target area (INOUT1>=0 false)
 * sender position is realiable (PV_SE_exists, PAI_SE true)
 * sender outside target area (INOUT3<0)
 * --> greedy forwarding */
    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 2.0, 2.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_sender)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car1, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 6.0, -2.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car2, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 6.0, 8.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car3, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, -2.0, 0.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(cBroadcastMacAddress, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 2.0, 2.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car1, test.get_interface(addy_sender)->last_request.destination);

    gbc_request.destination = circle_dest_area(1.0, 20.0, 0.0);
    confirm = test.get_router(addy_sender)->request(gbc_request,std::move(duplicate(*(test.get_interface(addy_sender))->last_packet)));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(addy_car2, test.get_interface(addy_sender)->last_request.destination);
}

TEST_F(Routing, advanced_forwarding_out_destarea_sender_in_destarea) {
/* Test-Scenario
 * GeoAdhocRouter outside target area (INOUT1>=0 false)
 * sender position is realiable (PV_SE_exists, PAI_SE true)
 * sender inside target area (INOUT3<0)
 * --> discard packet, return -1 */
    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 0.0, 0.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    auto confirm = test.get_router(addy_sender)->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    test.dispatch();

    EXPECT_TRUE(test.get_counter_indications() != 0);
    auto found = test.get_router(addy_car1)->get_cbf_buffer().find(addy_sender, SequenceNumber(0));
    EXPECT_FALSE(!!found);
    found = test.get_router(addy_car2)->get_cbf_buffer().find(addy_sender, SequenceNumber(0));
    EXPECT_FALSE(!!found);
    found = test.get_router(addy_car3)->get_cbf_buffer().find(addy_sender, SequenceNumber(0));
    EXPECT_FALSE(!!found);
}

TEST_F(Routing, advanced_forwarding_out_destarea_senderpos_not_reliable) {
/* Test-Scenario
 * GeoAdhocRouter outside target area (INOUT1>=0 false)
 * sender position is not realiable (PV_SE_exists, PAI_SE false)
 * --> next hop = broadcast */
    auto sender = test.get_router(addy_sender);
    LongPositionVector lpv = sender->get_local_position_vector();
    lpv.position_accuracy_indicator = false;
    sender->update(lpv);
    test.advance_time(1000 * Timestamp::millisecond);
    test.reset_counters();

    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 18.0, 6.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    test.get_interface(addy_sender)->last_packet.reset();
    EXPECT_FALSE(!!test.get_interface(addy_sender)->last_packet);
    auto confirm = sender->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_TRUE(!!test.get_interface(addy_sender)->last_packet);
    EXPECT_EQ(addy_car3, test.get_interface(addy_sender)->last_request.destination);

    ASSERT_EQ(0, test.get_counter_indications());
    ASSERT_EQ(1, test.get_counter_requests(addy_sender));
    test.dispatch();
    ASSERT_EQ(1, test.get_counter_indications());

    EXPECT_EQ(1, test.get_counter_requests(addy_sender));
    EXPECT_EQ(1, test.get_counter_requests(addy_car3));
    EXPECT_EQ(cBroadcastMacAddress, test.get_interface(addy_car3)->last_request.destination);
}

TEST_F(Routing, advanced_forwarding_out_destarea_senderpos_reliable) {
    auto sender = test.get_router(addy_sender);
    LongPositionVector lpv = sender->get_local_position_vector();
    lpv.position_accuracy_indicator = true;
    sender->update(lpv);
    test.advance_time(1000 * Timestamp::millisecond);
    test.reset_counters();

    GbcDataRequest gbc_request(test.get_mib());
    gbc_request.destination = circle_dest_area(1.0, 18.0, 6.0);
    gbc_request.upper_protocol = UpperProtocol::IPv6;
    test.get_interface(addy_sender)->last_packet.reset();
    EXPECT_FALSE(!!test.get_interface(addy_sender)->last_packet);
    auto confirm = sender->request(gbc_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_TRUE(!!test.get_interface(addy_sender)->last_packet);
    EXPECT_EQ(addy_car3, test.get_interface(addy_sender)->last_request.destination);

    ASSERT_EQ(0, test.get_counter_indications());
    ASSERT_EQ(1, test.get_counter_requests(addy_sender));
    test.dispatch();
    ASSERT_EQ(1, test.get_counter_indications());

    EXPECT_EQ(1, test.get_counter_requests(addy_sender));
    EXPECT_EQ(1, test.get_counter_requests(addy_car3));
    EXPECT_EQ(addy_car4, test.get_interface(addy_car3)->last_request.destination);
}
