#include <gtest/gtest.h>
#include <vanetza/asn1/its/NodeXY.h>
#include <vanetza/asn1/mapem.hpp>
#include <vanetza/asn1/spatem.hpp>
#include <algorithm>
#include <initializer_list>
#include <stdexcept>

using namespace vanetza;

namespace
{

// fill BIT STRING with given bytes and number of significant bits
void set_bits(BIT_STRING_t& bits, std::initializer_list<uint8_t> bytes, int nbits)
{
    bits.size = bytes.size();
    bits.buf = static_cast<uint8_t*>(asn1::allocate(bits.size));
    std::copy(bytes.begin(), bytes.end(), bits.buf);
    bits.bits_unused = static_cast<int>(bits.size * 8) - nbits;
}

void fill_header(ItsPduHeader_t& header, long message_id)
{
    header.protocolVersion = 2;
    header.messageID = message_id;
    header.stationID = 1337;
}

// one intersection, one signal group with a protected green and timing forecast
void fill_spatem(asn1::Spatem& spatem)
{
    fill_header(spatem->header, ItsPduHeader__messageID_spatem);

    auto intersection = asn1::allocate<IntersectionState_t>();
    intersection->id.id = 42;
    intersection->revision = 1;
    set_bits(intersection->status, {0x00, 0x00}, 16);

    auto movement = asn1::allocate<MovementState_t>();
    movement->signalGroup = 1;

    auto event = asn1::allocate<MovementEvent_t>();
    event->eventState = MovementPhaseState_protected_Movement_Allowed;
    event->timing = asn1::allocate<TimeChangeDetails_t>();
    event->timing->minEndTime = 300;
    event->timing->maxEndTime = asn1::allocate<TimeMark_t>();
    *event->timing->maxEndTime = 450;
    event->timing->likelyTime = asn1::allocate<TimeMark_t>();
    *event->timing->likelyTime = 350;
    event->timing->confidence = asn1::allocate<TimeIntervalConfidence_t>();
    *event->timing->confidence = 10;

    ASSERT_EQ(0, ASN_SEQUENCE_ADD(&movement->state_time_speed, event));
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(&intersection->states, movement));
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(&spatem->spat.intersections, intersection));
}

// LaneDirection ::= BIT STRING { ingressPath(0), egressPath(1) } (SIZE(2))
const uint8_t ingress_path = 0x80;
const uint8_t egress_path = 0x40;

GenericLane_t* make_lane(long lane_id, uint8_t direction, long x, long y)
{
    auto lane = asn1::allocate<GenericLane_t>();
    lane->laneID = lane_id;
    set_bits(lane->laneAttributes.directionalUse, {direction}, 2);
    set_bits(lane->laneAttributes.sharedWith, {0x00, 0x00}, 10);
    lane->laneAttributes.laneType.present = LaneTypeAttributes_PR_vehicle;
    set_bits(lane->laneAttributes.laneType.choice.vehicle, {0x00}, 8);

    lane->nodeList.present = NodeListXY_PR_nodes;
    for (long scale : {1, 2}) {
        auto node = asn1::allocate<NodeXY_t>();
        node->delta.present = NodeOffsetPointXY_PR_node_XY1;
        node->delta.choice.node_XY1.x = x * scale;
        node->delta.choice.node_XY1.y = y * scale;
        EXPECT_EQ(0, ASN_SEQUENCE_ADD(&lane->nodeList.choice.nodes, node));
    }
    return lane;
}

// one intersection with an ingress lane connected to an egress lane via signal group 1
void fill_mapem(asn1::Mapem& mapem)
{
    fill_header(mapem->header, ItsPduHeader__messageID_mapem);
    mapem->map.msgIssueRevision = 1;

    auto geometry = asn1::allocate<IntersectionGeometry_t>();
    geometry->id.id = 42;
    geometry->revision = 1;
    geometry->refPoint.lat = 599000000; // 1/10 micro degree
    geometry->refPoint.Long = 303000000;

    auto ingress = make_lane(1, ingress_path, 100, 0);
    ingress->connectsTo = asn1::allocate<ConnectsToList_t>();
    auto connection = asn1::allocate<Connection_t>();
    connection->connectingLane.lane = 2;
    connection->signalGroup = asn1::allocate<SignalGroupID_t>();
    *connection->signalGroup = 1;
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(ingress->connectsTo, connection));
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(&geometry->laneSet, ingress));
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(&geometry->laneSet, make_lane(2, egress_path, 0, 100)));

    mapem->map.intersections = asn1::allocate<IntersectionGeometryList_t>();
    ASSERT_EQ(0, ASN_SEQUENCE_ADD(mapem->map.intersections, geometry));
}

} // namespace

TEST(SpatemMapemAsn1, spatem_roundtrip)
{
    asn1::Spatem tx;
    fill_spatem(tx);
    std::string error;
    ASSERT_TRUE(tx.validate(error)) << error;

    const ByteBuffer buffer = tx.encode();
    EXPECT_EQ(tx.size(), buffer.size());

    asn1::Spatem rx;
    ASSERT_TRUE(rx.decode(buffer));
    EXPECT_EQ(0, tx.compare(rx));

    EXPECT_EQ(ItsPduHeader__messageID_spatem, rx->header.messageID);
    ASSERT_EQ(1, rx->spat.intersections.list.count);
    const IntersectionState_t* intersection = rx->spat.intersections.list.array[0];
    EXPECT_EQ(42, intersection->id.id);
    ASSERT_EQ(1, intersection->states.list.count);
    const MovementState_t* movement = intersection->states.list.array[0];
    EXPECT_EQ(1, movement->signalGroup);
    ASSERT_EQ(1, movement->state_time_speed.list.count);
    const MovementEvent_t* event = movement->state_time_speed.list.array[0];
    EXPECT_EQ(MovementPhaseState_protected_Movement_Allowed, event->eventState);
    ASSERT_NE(nullptr, event->timing);
    EXPECT_EQ(300, event->timing->minEndTime);
    ASSERT_NE(nullptr, event->timing->maxEndTime);
    EXPECT_EQ(450, *event->timing->maxEndTime);
    ASSERT_NE(nullptr, event->timing->likelyTime);
    EXPECT_EQ(350, *event->timing->likelyTime);
    ASSERT_NE(nullptr, event->timing->confidence);
    EXPECT_EQ(10, *event->timing->confidence);
}

TEST(SpatemMapemAsn1, mapem_roundtrip)
{
    asn1::Mapem tx;
    fill_mapem(tx);
    std::string error;
    ASSERT_TRUE(tx.validate(error)) << error;

    const ByteBuffer buffer = tx.encode();
    asn1::Mapem rx;
    ASSERT_TRUE(rx.decode(buffer));
    EXPECT_EQ(0, tx.compare(rx));

    EXPECT_EQ(ItsPduHeader__messageID_mapem, rx->header.messageID);
    ASSERT_NE(nullptr, rx->map.intersections);
    ASSERT_EQ(1, rx->map.intersections->list.count);
    const IntersectionGeometry_t* geometry = rx->map.intersections->list.array[0];
    EXPECT_EQ(599000000, geometry->refPoint.lat);
    ASSERT_EQ(2, geometry->laneSet.list.count);
    const GenericLane_t* ingress = geometry->laneSet.list.array[0];
    ASSERT_NE(nullptr, ingress->connectsTo);
    ASSERT_EQ(1, ingress->connectsTo->list.count);
    const Connection_t* connection = ingress->connectsTo->list.array[0];
    EXPECT_EQ(2, connection->connectingLane.lane);
    ASSERT_NE(nullptr, connection->signalGroup);
    EXPECT_EQ(1, *connection->signalGroup);
}

TEST(SpatemMapemAsn1, spatem_revision_out_of_range)
{
    asn1::Spatem spatem;
    fill_spatem(spatem);
    spatem->spat.intersections.list.array[0]->revision = 127;
    EXPECT_TRUE(spatem.validate());
    EXPECT_NO_THROW(spatem.encode());
    spatem->spat.intersections.list.array[0]->revision = 128; // MsgCount ::= INTEGER (0..127)
    EXPECT_FALSE(spatem.validate());
    EXPECT_THROW(spatem.encode(), std::runtime_error);
}

TEST(SpatemMapemAsn1, mapem_revision_out_of_range)
{
    asn1::Mapem mapem;
    fill_mapem(mapem);
    mapem->map.msgIssueRevision = 127;
    EXPECT_TRUE(mapem.validate());
    EXPECT_NO_THROW(mapem.encode());
    mapem->map.msgIssueRevision = 128; // MsgCount ::= INTEGER (0..127)
    EXPECT_FALSE(mapem.validate());
    EXPECT_THROW(mapem.encode(), std::runtime_error);
}

TEST(SpatemMapemAsn1, spatem_time_mark_out_of_range)
{
    asn1::Spatem spatem;
    fill_spatem(spatem);
    auto event = spatem->spat.intersections.list.array[0]->states.list.array[0]->state_time_speed.list.array[0];
    event->timing->minEndTime = 36001; // "unknown" is still valid
    EXPECT_TRUE(spatem.validate());
    EXPECT_NO_THROW(spatem.encode());
    event->timing->minEndTime = 36002; // TimeMark ::= INTEGER (0..36001)
    EXPECT_FALSE(spatem.validate());
    EXPECT_THROW(spatem.encode(), std::runtime_error);
}

TEST(SpatemMapemAsn1, spatem_signal_group_out_of_range)
{
    asn1::Spatem spatem;
    fill_spatem(spatem);
    spatem->spat.intersections.list.array[0]->states.list.array[0]->signalGroup = 255;
    EXPECT_TRUE(spatem.validate());
    EXPECT_NO_THROW(spatem.encode());
    spatem->spat.intersections.list.array[0]->states.list.array[0]->signalGroup = 256; // SignalGroupID ::= INTEGER (0..255)
    EXPECT_FALSE(spatem.validate());
    EXPECT_THROW(spatem.encode(), std::runtime_error);
}

TEST(SpatemMapemAsn1, spatem_empty_movement_list)
{
    asn1::Spatem spatem;
    fill_spatem(spatem);
    auto intersection = spatem->spat.intersections.list.array[0];
    MovementState_t* movement = intersection->states.list.array[0];
    asn_sequence_empty(&intersection->states); // MovementList ::= SEQUENCE (SIZE(1..255))
    ASN_STRUCT_FREE(asn_DEF_MovementState, movement);
    // the SEQUENCE OF size constraint is enforced at the latest by the encoder
    EXPECT_THROW(spatem.encode(), std::runtime_error);
}

TEST(SpatemMapemAsn1, spatem_decode_truncated)
{
    asn1::Spatem tx;
    fill_spatem(tx);
    ByteBuffer buffer = tx.encode();
    ASSERT_GT(buffer.size(), 2u);

    for (std::size_t length : {std::size_t(0), std::size_t(1), buffer.size() / 2, buffer.size() - 1}) {
        asn1::Spatem rx;
        const ByteBuffer truncated(buffer.begin(), buffer.begin() + length);
        EXPECT_FALSE(rx.decode(truncated)) << "length " << length;
    }
}

TEST(SpatemMapemAsn1, mapem_decode_truncated)
{
    asn1::Mapem tx;
    fill_mapem(tx);
    ByteBuffer buffer = tx.encode();
    ASSERT_GT(buffer.size(), 2u);

    for (std::size_t length : {std::size_t(0), std::size_t(1), buffer.size() / 2, buffer.size() - 1}) {
        asn1::Mapem rx;
        const ByteBuffer truncated(buffer.begin(), buffer.begin() + length);
        EXPECT_FALSE(rx.decode(truncated)) << "length " << length;
    }
}
