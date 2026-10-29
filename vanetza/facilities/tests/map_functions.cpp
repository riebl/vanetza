#include <gtest/gtest.h>
#include <vanetza/asn1/its/NodeXY.h>
#include <vanetza/asn1/mapem.hpp>
#include <vanetza/facilities/map_functions.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <stdexcept>

using namespace vanetza;
using namespace vanetza::facilities;

namespace
{

const auto meter = units::si::meter;

const NodeXY_t& node(const GenericLane_t& lane, int index)
{
    return *lane.nodeList.choice.nodes.list.array[index];
}

bool bit(const BIT_STRING_t& bits, int index)
{
    return bits.buf[index / 8] & (0x80 >> (index % 8));
}

int bit_count(const BIT_STRING_t& bits)
{
    int count = 0;
    for (std::size_t i = 0; i < bits.size; ++i) {
        for (uint8_t b = bits.buf[i]; b; b &= b - 1) {
            ++count;
        }
    }
    return count;
}

} // namespace

TEST(MapFunctions, build_mapem)
{
    asn1::Mapem mapem;
    mapem->header.protocolVersion = 2;
    mapem->header.messageID = ItsPduHeader__messageID_mapem;
    mapem->header.stationID = 1337;
    mapem->map.msgIssueRevision = 0;

    IntersectionGeometry& intersection = add_intersection_geometry(mapem->map, 42, 3,
        59.9386 * units::degree, 30.3141 * units::degree, 3.5 * meter);
    GenericLane& ingress = add_vehicle_lane(intersection, 1, TravelDirection::Ingress, 1);
    add_node(ingress, 2.0 * meter, -15.0 * meter);
    add_node(ingress, 0.0 * meter, -20.0 * meter);
    connect(ingress, 2, Maneuver::Left, 5, 7);
    GenericLane& egress = add_vehicle_lane(intersection, 2, TravelDirection::Egress, 2);
    add_node(egress, 15.0 * meter, 2.0 * meter);
    add_node(egress, 20.0 * meter, 0.0 * meter);

    std::string error;
    ASSERT_TRUE(mapem.validate(error)) << error;
    asn1::Mapem decoded;
    ASSERT_TRUE(decoded.decode(mapem.encode()));

    ASSERT_NE(nullptr, decoded->map.intersections);
    const IntersectionGeometry_t* rx = decoded->map.intersections->list.array[0];
    EXPECT_EQ(42, rx->id.id);
    EXPECT_EQ(3, rx->revision);
    EXPECT_EQ(599386000, rx->refPoint.lat);
    EXPECT_EQ(303141000, rx->refPoint.Long);
    ASSERT_NE(nullptr, rx->laneWidth);
    EXPECT_EQ(350, *rx->laneWidth);
    ASSERT_EQ(2, rx->laneSet.list.count);

    const GenericLane_t& rx_ingress = *rx->laneSet.list.array[0];
    EXPECT_EQ(1, rx_ingress.laneID);
    EXPECT_EQ(0x80, rx_ingress.laneAttributes.directionalUse.buf[0]); // ingressPath only
    ASSERT_NE(nullptr, rx_ingress.ingressApproach);
    EXPECT_EQ(1, *rx_ingress.ingressApproach);
    EXPECT_EQ(nullptr, rx_ingress.egressApproach);
    EXPECT_EQ(nullptr, rx_ingress.maneuvers); // C2C RS_ARSM_117
    ASSERT_EQ(2, rx_ingress.nodeList.choice.nodes.list.count);
    // 15 m needs Node-XY-24b (-2048..2047 cm)
    EXPECT_EQ(NodeOffsetPointXY_PR_node_XY3, node(rx_ingress, 0).delta.present);
    EXPECT_EQ(200, node(rx_ingress, 0).delta.choice.node_XY3.x);
    EXPECT_EQ(-1500, node(rx_ingress, 0).delta.choice.node_XY3.y);

    ASSERT_NE(nullptr, rx_ingress.connectsTo);
    ASSERT_EQ(1, rx_ingress.connectsTo->list.count);
    const Connection_t& connection = *rx_ingress.connectsTo->list.array[0];
    EXPECT_EQ(2, connection.connectingLane.lane);
    ASSERT_NE(nullptr, connection.connectingLane.maneuver);
    EXPECT_EQ(1, bit_count(*connection.connectingLane.maneuver)); // C2C RS_ARSM_22
    EXPECT_TRUE(bit(*connection.connectingLane.maneuver, AllowedManeuvers_maneuverLeftAllowed));
    ASSERT_NE(nullptr, connection.signalGroup);
    EXPECT_EQ(5, *connection.signalGroup);
    ASSERT_NE(nullptr, connection.connectionID);
    EXPECT_EQ(7, *connection.connectionID);

    const GenericLane_t& rx_egress = *rx->laneSet.list.array[1];
    EXPECT_EQ(0x40, rx_egress.laneAttributes.directionalUse.buf[0]); // egressPath only
    ASSERT_NE(nullptr, rx_egress.egressApproach);
    EXPECT_EQ(2, *rx_egress.egressApproach);
    EXPECT_EQ(nullptr, rx_egress.ingressApproach);
    EXPECT_EQ(nullptr, rx_egress.connectsTo);
}

TEST(MapFunctions, tram_and_crosswalk_lanes)
{
    asn1::Mapem mapem;
    IntersectionGeometry& intersection = add_intersection_geometry(mapem->map, 1, 0,
        0.0 * units::degree, 0.0 * units::degree, 3.5 * meter);

    GenericLane& tram = add_tram_lane(intersection, 10, TravelDirection::Ingress, 1);
    add_node(tram, 0.0 * meter, 12.0 * meter);
    add_node(tram, 0.0 * meter, 40.0 * meter);
    connect(tram, 11, Maneuver::Straight, 9, 1);
    GenericLane& tram_out = add_tram_lane(intersection, 11, TravelDirection::Egress, 2);
    add_node(tram_out, 0.0 * meter, -12.0 * meter);
    add_node(tram_out, 0.0 * meter, -40.0 * meter);

    GenericLane& crosswalk = add_crosswalk_lane(intersection, 20, 1, 3);
    add_node(crosswalk, -7.0 * meter, 11.0 * meter);
    add_node(crosswalk, 14.0 * meter, 0.0 * meter);
    connect(crosswalk, 20, Maneuver::Straight, 5, 2);

    std::string error;
    ASSERT_TRUE(mapem.validate(error)) << error;
    asn1::Mapem decoded;
    ASSERT_TRUE(decoded.decode(mapem.encode()));
    const IntersectionGeometry_t* rx = decoded->map.intersections->list.array[0];
    ASSERT_EQ(3, rx->laneSet.list.count);

    const GenericLane_t& rx_tram = *rx->laneSet.list.array[0];
    ASSERT_EQ(LaneTypeAttributes_PR_trackedVehicle, rx_tram.laneAttributes.laneType.present);
    EXPECT_TRUE(bit(rx_tram.laneAttributes.laneType.choice.trackedVehicle,
        LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack));

    const GenericLane_t& rx_crosswalk = *rx->laneSet.list.array[2];
    ASSERT_EQ(LaneTypeAttributes_PR_crosswalk, rx_crosswalk.laneAttributes.laneType.present);
    EXPECT_EQ(0xc0, rx_crosswalk.laneAttributes.directionalUse.buf[0]); // both directions
    ASSERT_NE(nullptr, rx_crosswalk.ingressApproach); // C2C RS_ARSM_17
    ASSERT_NE(nullptr, rx_crosswalk.egressApproach);
    EXPECT_EQ(1, *rx_crosswalk.ingressApproach);
    EXPECT_EQ(3, *rx_crosswalk.egressApproach);
    ASSERT_NE(nullptr, rx_crosswalk.connectsTo);
    EXPECT_EQ(5, *rx_crosswalk.connectsTo->list.array[0]->signalGroup);
}

TEST(MapFunctions, node_offset_representation)
{
    asn1::Mapem mapem;
    IntersectionGeometry& intersection = add_intersection_geometry(mapem->map, 1, 0,
        0.0 * units::degree, 0.0 * units::degree, 3.5 * meter);
    GenericLane& lane = add_vehicle_lane(intersection, 1, TravelDirection::Both, 1);

    add_node(lane, 5.11 * meter, -5.12 * meter); // boundary of Node-XY-20b
    add_node(lane, 5.12 * meter, 0.0 * meter); // just beyond
    add_node(lane, 327.67 * meter, -327.68 * meter); // boundary of Node-XY-32b
    EXPECT_THROW(add_node(lane, 327.68 * meter, 0.0 * meter), std::out_of_range);

    ASSERT_EQ(3, lane.nodeList.choice.nodes.list.count);
    EXPECT_EQ(NodeOffsetPointXY_PR_node_XY1, node(lane, 0).delta.present);
    EXPECT_EQ(511, node(lane, 0).delta.choice.node_XY1.x);
    EXPECT_EQ(-512, node(lane, 0).delta.choice.node_XY1.y);
    EXPECT_EQ(NodeOffsetPointXY_PR_node_XY2, node(lane, 1).delta.present);
    EXPECT_EQ(NodeOffsetPointXY_PR_node_XY6, node(lane, 2).delta.present);
    EXPECT_EQ(0xc0, lane.laneAttributes.directionalUse.buf[0]); // ingress and egress
}
