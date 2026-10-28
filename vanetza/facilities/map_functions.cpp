#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/ConnectsToList.h>
#include <vanetza/asn1/its/GenericLane.h>
#include <vanetza/asn1/its/IntersectionGeometry.h>
#include <vanetza/asn1/its/IntersectionGeometryList.h>
#include <vanetza/asn1/its/MapData.h>
#include <vanetza/asn1/its/NodeXY.h>
#include <vanetza/facilities/map_functions.hpp>
#include <boost/units/cmath.hpp>
#include <boost/units/systems/angle/degrees.hpp>
#include <boost/units/systems/si/prefixes.hpp>
#include <cmath>
#include <stdexcept>

namespace vanetza
{
namespace facilities
{

namespace
{

static const auto tenth_microdegree = units::si::deci * units::degree * units::si::micro;
static const auto centimeter = units::si::centi * units::si::meter;

template<typename T, typename U>
long round(const boost::units::quantity<T>& q, const U&)
{
    return std::lround(boost::units::quantity<U>(q).value());
}

void set_bits(BIT_STRING_t& bits, std::size_t bytes, int size)
{
    bits.size = bytes;
    bits.buf = static_cast<uint8_t*>(asn1::allocate(bytes));
    bits.bits_unused = static_cast<int>(bytes * 8) - size;
}

void set_bit(BIT_STRING_t& bits, int bit)
{
    bits.buf[bit / 8] |= 0x80 >> (bit % 8);
}

// Offset-B<bits> ::= INTEGER (-2^(bits-1) .. 2^(bits-1)-1), unit 1 cm
bool fits(long x, long y, int bits)
{
    const long min = -(1L << (bits - 1));
    const long max = (1L << (bits - 1)) - 1;
    return x >= min && x <= max && y >= min && y <= max;
}

template<typename NODE>
void set_offset(NODE& node, long x, long y)
{
    node.x = x;
    node.y = y;
}

} // namespace

IntersectionGeometry& add_intersection_geometry(MapData& map, long id, long revision,
        units::GeoAngle latitude, units::GeoAngle longitude, units::Length lane_width)
{
    auto geometry = asn1::make_unique<IntersectionGeometry_t>(asn_DEF_IntersectionGeometry);
    geometry->id.id = id;
    geometry->revision = revision;
    geometry->refPoint.lat = round(latitude, tenth_microdegree);
    geometry->refPoint.Long = round(longitude, tenth_microdegree);
    *asn1::allocate_optional(geometry->laneWidth) = round(lane_width, centimeter);
    return asn1::append(*asn1::allocate_optional(map.intersections), std::move(geometry));
}

namespace
{

GenericLane& add_lane(IntersectionGeometry& intersection, long lane_id, TravelDirection direction,
        long ingress_approach, long egress_approach)
{
    auto lane = asn1::make_unique<GenericLane_t>(asn_DEF_GenericLane);
    lane->laneID = lane_id;

    LaneAttributes_t& attributes = lane->laneAttributes;
    set_bits(attributes.directionalUse, 1, 2);
    if (direction != TravelDirection::Egress) {
        set_bit(attributes.directionalUse, LaneDirection_ingressPath);
        *asn1::allocate_optional(lane->ingressApproach) = ingress_approach;
    }
    if (direction != TravelDirection::Ingress) {
        set_bit(attributes.directionalUse, LaneDirection_egressPath);
        *asn1::allocate_optional(lane->egressApproach) = egress_approach;
    }
    set_bits(attributes.sharedWith, 2, 10);

    lane->nodeList.present = NodeListXY_PR_nodes;
    return asn1::append(intersection.laneSet, std::move(lane));
}

} // namespace

GenericLane& add_vehicle_lane(IntersectionGeometry& intersection, long lane_id, TravelDirection direction, long approach)
{
    GenericLane& lane = add_lane(intersection, lane_id, direction, approach, approach);
    LaneTypeAttributes_t& type = lane.laneAttributes.laneType;
    type.present = LaneTypeAttributes_PR_vehicle;
    set_bits(type.choice.vehicle, 1, 8);
    return lane;
}

GenericLane& add_tram_lane(IntersectionGeometry& intersection, long lane_id, TravelDirection direction, long approach)
{
    GenericLane& lane = add_lane(intersection, lane_id, direction, approach, approach);
    LaneTypeAttributes_t& type = lane.laneAttributes.laneType;
    type.present = LaneTypeAttributes_PR_trackedVehicle;
    set_bits(type.choice.trackedVehicle, 2, 16);
    set_bit(type.choice.trackedVehicle, LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack);
    return lane;
}

GenericLane& add_crosswalk_lane(IntersectionGeometry& intersection, long lane_id,
        long ingress_approach, long egress_approach)
{
    GenericLane& lane = add_lane(intersection, lane_id, TravelDirection::Both, ingress_approach, egress_approach);
    LaneTypeAttributes_t& type = lane.laneAttributes.laneType;
    type.present = LaneTypeAttributes_PR_crosswalk;
    set_bits(type.choice.crosswalk, 2, 16);
    return lane;
}

void add_node(GenericLane& lane, units::Length east, units::Length north)
{
    if (lane.nodeList.present != NodeListXY_PR_nodes) {
        throw std::invalid_argument("lane has no node list");
    }

    const long x = round(east, centimeter);
    const long y = round(north, centimeter);

    auto node = asn1::make_unique<NodeXY_t>(asn_DEF_NodeXY);
    NodeOffsetPointXY_t& delta = node->delta;
    if (fits(x, y, 10)) {
        delta.present = NodeOffsetPointXY_PR_node_XY1;
        set_offset(delta.choice.node_XY1, x, y);
    } else if (fits(x, y, 11)) {
        delta.present = NodeOffsetPointXY_PR_node_XY2;
        set_offset(delta.choice.node_XY2, x, y);
    } else if (fits(x, y, 12)) {
        delta.present = NodeOffsetPointXY_PR_node_XY3;
        set_offset(delta.choice.node_XY3, x, y);
    } else if (fits(x, y, 13)) {
        delta.present = NodeOffsetPointXY_PR_node_XY4;
        set_offset(delta.choice.node_XY4, x, y);
    } else if (fits(x, y, 14)) {
        delta.present = NodeOffsetPointXY_PR_node_XY5;
        set_offset(delta.choice.node_XY5, x, y);
    } else if (fits(x, y, 16)) {
        delta.present = NodeOffsetPointXY_PR_node_XY6;
        set_offset(delta.choice.node_XY6, x, y);
    } else {
        throw std::out_of_range("node offset exceeds Node-XY-32b");
    }
    asn1::append(lane.nodeList.choice.nodes, std::move(node));
}

void connect(GenericLane& from, long lane_id, Maneuver maneuver, long signal_group, long connection_id)
{
    auto connection = asn1::make_unique<Connection_t>(asn_DEF_Connection);
    connection->connectingLane.lane = lane_id;
    // exactly one direction bit per connection (C2C-CC RS 2077, RS_ARSM_22)
    AllowedManeuvers_t* bits = asn1::allocate_optional(connection->connectingLane.maneuver);
    set_bits(*bits, 2, 12);
    switch (maneuver) {
        case Maneuver::Straight:
            set_bit(*bits, AllowedManeuvers_maneuverStraightAllowed);
            break;
        case Maneuver::Left:
            set_bit(*bits, AllowedManeuvers_maneuverLeftAllowed);
            break;
        case Maneuver::Right:
            set_bit(*bits, AllowedManeuvers_maneuverRightAllowed);
            break;
        case Maneuver::UTurn:
            set_bit(*bits, AllowedManeuvers_maneuverUTurnAllowed);
            break;
    }
    *asn1::allocate_optional(connection->signalGroup) = signal_group;
    *asn1::allocate_optional(connection->connectionID) = connection_id;
    asn1::append(*asn1::allocate_optional(from.connectsTo), std::move(connection));
}

} // namespace facilities
} // namespace vanetza
