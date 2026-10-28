#ifndef MAP_FUNCTIONS_HPP_W6N2RXJD
#define MAP_FUNCTIONS_HPP_W6N2RXJD

#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

// forward declaration of asn1c generated struct
struct GenericLane;
struct IntersectionGeometry;
struct MapData;

namespace vanetza
{
namespace facilities
{

/**
 * Builders for MAPEM intersection topology (ETSI TS 103 301, ISO TS 19091 DSRC data elements).
 *
 * The builders follow the C2C-CC RS 2077 profile: reference lane width per intersection,
 * exactly one manoeuvre per connection and no manoeuvres on lane level.
 * They leave the road regulator (IntersectionReferenceID.region) empty; where the profile
 * requires it together with the identifier (RS_ARSM_11), the caller sets the same value
 * in MAPEM and SPATEM.
 */

/**
 * Append an intersection geometry to MapData
 * \param map MapData container (destination)
 * \param id intersection identifier unique within its road regulator (0..65535)
 * \param revision MsgCount of the intersection geometry (0..127), equal to SPATEM revision
 * \param latitude WGS84 latitude of the reference point
 * \param longitude WGS84 longitude of the reference point
 * \param lane_width reference width of all lanes of this intersection
 * \return appended intersection geometry, owned by map
 * \throw asn1::asn1c_exception if memory allocation fails
 */
IntersectionGeometry& add_intersection_geometry(MapData& map, long id, long revision,
        units::GeoAngle latitude, units::GeoAngle longitude, units::Length lane_width);

/**
 * Travel direction of a lane relative to the intersection
 */
enum class TravelDirection
{
    Ingress, /**< lane leads into the intersection */
    Egress, /**< lane leads away from the intersection */
    Both
};

/**
 * Manoeuvre of a connection from an ingress lane to a connecting lane
 */
enum class Maneuver
{
    Straight,
    Left,
    Right,
    UTurn
};

/**
 * Append a motor vehicle lane to an intersection geometry
 * \param intersection intersection geometry (destination)
 * \param lane_id lane identifier unique within the intersection (0..255)
 * \param direction travel direction
 * \param approach approach (intersection arm) identifier (0..15)
 * \return appended lane, owned by intersection
 * \throw asn1::asn1c_exception if memory allocation fails
 */
GenericLane& add_vehicle_lane(IntersectionGeometry& intersection, long lane_id, TravelDirection direction, long approach);

/**
 * Append a tram track (light rail) to an intersection geometry
 * \param intersection intersection geometry (destination)
 * \param lane_id lane identifier unique within the intersection (0..255)
 * \param direction travel direction
 * \param approach approach (intersection arm) identifier (0..15)
 * \return appended lane, owned by intersection
 * \throw asn1::asn1c_exception if memory allocation fails
 */
GenericLane& add_tram_lane(IntersectionGeometry& intersection, long lane_id, TravelDirection direction, long approach);

/**
 * Append a pedestrian crosswalk to an intersection geometry
 *
 * A crosswalk is used in both directions and crosses the ingress and egress side of an arm,
 * hence both approach identifiers are set (C2C-CC RS 2077, RS_ARSM_17).
 *
 * \param intersection intersection geometry (destination)
 * \param lane_id lane identifier unique within the intersection (0..255)
 * \param ingress_approach approach identifier of the crossed ingress side (0..15)
 * \param egress_approach approach identifier of the crossed egress side (0..15)
 * \return appended lane, owned by intersection
 * \throw asn1::asn1c_exception if memory allocation fails
 */
GenericLane& add_crosswalk_lane(IntersectionGeometry& intersection, long lane_id,
        long ingress_approach, long egress_approach);

/**
 * Append a node to the lane centre line
 *
 * Lanes are described from the stop line outwards, i.e. the first node of an ingress lane
 * is its stop line (C2C-CC RS 2077, RS_ARSM_26). The offset is relative to the previous
 * node, for the first node relative to the intersection reference point. It is encoded with
 * centimetre resolution using the smallest Node-XY representation able to hold both components.
 *
 * \param lane lane (destination)
 * \param east offset towards east
 * \param north offset towards north
 * \throw std::out_of_range if an offset exceeds the Node-XY-32b range
 * \throw asn1::asn1c_exception if memory allocation fails
 */
void add_node(GenericLane& lane, units::Length east, units::Length north);

/**
 * Connect a lane to a lane it leads to, controlled by a signal group
 * \param from lane (destination)
 * \param lane_id identifier of the connected lane within the same intersection (0..255)
 * \param maneuver manoeuvre of this connection
 * \param signal_group signal group controlling this connection (0..255)
 * \param connection_id identifier unique within the intersection (0..255)
 * \throw asn1::asn1c_exception if memory allocation fails
 */
void connect(GenericLane& from, long lane_id, Maneuver maneuver, long signal_group, long connection_id);

} // namespace facilities
} // namespace vanetza

#endif /* MAP_FUNCTIONS_HPP_W6N2RXJD */
