#ifndef REGION_HPP_NUISLPMU
#define REGION_HPP_NUISLPMU

#include <vanetza/geonet/units.hpp>
#include <vanetza/security/int_x.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>
#include <boost/variant/variant.hpp>
#include <list>

namespace vanetza
{
namespace security
{

/// ThreeDLocation specified in TS 103 097 v1.2.1, section 4.2.19
struct ThreeDLocation
{
    using Elevation = std::array<uint8_t, 2>;
    static const Elevation unknown_elevation;
    static const Elevation min_elevation;
    static const Elevation max_elevation;

    ThreeDLocation() = default;
    ThreeDLocation(geonet::geo_angle_i32t latitude, geonet::geo_angle_i32t longitude) :
        latitude(latitude), longitude(longitude), elevation(unknown_elevation) {}
    ThreeDLocation(units::GeoAngle latitude, units::GeoAngle longitude) :
        latitude(latitude), longitude(longitude), elevation(unknown_elevation) {}
    ThreeDLocation(geonet::geo_angle_i32t latitude, geonet::geo_angle_i32t longitude, Elevation elevation) :
        latitude(latitude), longitude(longitude), elevation(elevation) {}
    ThreeDLocation(units::GeoAngle latitude, units::GeoAngle longitude, Elevation elevation) :
        latitude(latitude), longitude(longitude), elevation(elevation) {}

    geonet::geo_angle_i32t latitude;
    geonet::geo_angle_i32t longitude;
    Elevation elevation;

    bool operator==(const ThreeDLocation&) const;
    bool operator!=(const ThreeDLocation&) const;
};

/// TwoDLocation specified in TS 103 097 v1.2.1, section 4.2.18
struct TwoDLocation
{
    TwoDLocation() = default;
    TwoDLocation(geonet::geo_angle_i32t latitude, geonet::geo_angle_i32t longitude) :
        latitude(latitude), longitude(longitude) {}
    TwoDLocation(units::GeoAngle latitude, units::GeoAngle longitude) :
        latitude(latitude), longitude(longitude) {}
    explicit TwoDLocation(const ThreeDLocation& threeD) :
        latitude(threeD.latitude), longitude(threeD.longitude) {}

    geonet::geo_angle_i32t latitude;
    geonet::geo_angle_i32t longitude;

    bool operator==(const TwoDLocation&) const;
    bool operator!=(const TwoDLocation&) const;
};

/// Specified in TS 103 097 v1.2.1, section 4.2.20
struct NoneRegion
{
    // empty

    bool operator==(const NoneRegion&) const;
    bool operator!=(const NoneRegion&) const;
};

/// CircularRegion specified in TS 103 097 v1.2.1, section 4.2.22
struct CircularRegion
{
    CircularRegion() = default;
    CircularRegion(const TwoDLocation& center, geonet::distance_u16t radius) :
        center(center), radius(radius) {}
    CircularRegion(const TwoDLocation& center, units::Length radius) :
        center(center), radius(radius) {}

    TwoDLocation center;
    geonet::distance_u16t radius;

    bool operator==(const CircularRegion&) const;
    bool operator!=(const CircularRegion&) const;
};

/// RectangularRegion specified in TS 103 097 v1.2.1, section 4.2.23
struct RectangularRegion
{
    TwoDLocation northwest;
    TwoDLocation southeast;

    bool operator==(const RectangularRegion&) const;
    bool operator!=(const RectangularRegion&) const;
};

/// PolygonalRegion specified in TS 103 097 v1.2.1, section 4.2.24
using PolygonalRegion = std::list<TwoDLocation>;

/// RegionDictionary specified in TS 103 097 v1.2.1, section 4.2.26
enum class RegionDictionary : uint8_t
{
    ISO_3166_1 = 0,
    UN_Stats = 1,
};

/// IdentifiedRegion specified in TS 103 097 v1.2.1, section 4.2.25
struct IdentifiedRegion
{
    RegionDictionary region_dictionary;
    int16_t region_identifier;
    IntX local_region;

    bool operator==(const IdentifiedRegion&) const;
    bool operator!=(const IdentifiedRegion&) const;
};

/// RegionType specified in TS 103 097 v1.2.1, section 4.2.21
enum class RegionType : uint8_t
{
    None = 0,       // nothing
    Circle = 1,     // CircularRegion
    Rectangle = 2,  // std::list<RectangularRegion>
    Polygon = 3,    // PolygonalRegion
    ID = 4,         // IdentifiedRegion
};

/// GeographicRegion specified in TS 103 097 v1.2.1, section 4.2.20
using GeographicRegion = boost::variant<
    NoneRegion,
    CircularRegion,
    std::list<RectangularRegion>,
    PolygonalRegion,
    IdentifiedRegion
>;

/**
 * \brief Determines RegionType of a GeographicRegion
 * \param region
 * \return RegionType
 */
RegionType get_type(const GeographicRegion&);

/**
 * \brief Calculates size of a TwoDLocation
 * \param loc
 * \return number of octets needed to serialize the TwoDLocation
 */
size_t get_size(const TwoDLocation&);

/**
 * \brief Calculates size of a ThreeDLocation
 * \param log
 * \return number of octets needed to serialize the ThreeDLocation
 */
size_t get_size(const ThreeDLocation&);

/**
 * \brief Calculates size of a CircularRegion
 * \param reg
 * \return number of octets needed to serialize the CiruclarRegion
 */
size_t get_size(const CircularRegion&);

/**
 * \brief Calculates size of a RectangularRegion
 * \param reg
 * \return number of octets needed to serialize the RectangularRegion
 */
size_t get_size(const RectangularRegion&);

/**
 * \brief Calculates size of a list of CircularRegion
 * \param list
 * \return number of octets needed to serialize the list of CircularRegion
 */
size_t get_size(const std::list<CircularRegion>&);

/**
 * \brief Calculates size of a list of RectangularRegion
 * \param list
 * \return number of octets needed to serialize the list of RectangularRegion
 */
size_t get_size(const std::list<RectangularRegion>&);

/**
 * \brief Calculates size of a PolygonalRegion
 * \param reg
 * \return number of octets needed to serialize the PolygonalRegion
 */
size_t get_size(const PolygonalRegion&);

/**
 * \brief Calculates size of a GeographicRegion
 * \param reg
 * \return number of octets needed to serialize the GeographicRegion
 */
size_t get_size(const GeographicRegion&);

/**
 * \brief Serializes a TwoDLocation into a binary archive
 * \param ar to serialize in
 * \param loc to serialize
 */
void serialize(OutputArchive&, const TwoDLocation&);

/**
 * \brief Serializes a ThreeDLocation into a binary archive
 * \param ar to serialize in
 * \param loc to serialize
 */
void serialize(OutputArchive&, const ThreeDLocation&);

/**
 * \brief Serializes a CiruclarRegion into a binary archive
 * \param ar to serialize in
 * \param reg to serialize
 */
void serialize(OutputArchive&, const CircularRegion&);

/**
 * \brief Serializes a RectangularRegion into a binary archive
 * \param ar to serialize in
 * \param reg to serialize
 */
void serialize(OutputArchive&, const RectangularRegion&);

/**
 * \brief Serializes a list of RectangularRegions into a binary archive
 * \param ar to serialize in
 * \param list to serialize
 */
void serialize(OutputArchive&, const std::list<RectangularRegion>&);

/**
 * \brief Serializes a PolygonalRegion into a binary archive
 * \param ar to serialize in
 * \param reg to serialize
 */
void serialize(OutputArchive&, const PolygonalRegion&);

/**
 * \brief Serializes an IdentifiedRegion into a binary archive
 * \param ar to serialize in
 * \param reg to serialize
 */
void serialize(OutputArchive&, const IdentifiedRegion&);

/**
 * \brief Serializes a GeographicRegion into a binary archive
 * \param ar to serialize in
 * \param reg to serialize
 */
void serialize(OutputArchive&, const GeographicRegion&);

/**
 * \brief Deserializes a TwoDLocation from a binary archive
 * \param ar with a serialized TwoDLocation at the beginning
 * \param loc to deserialize
 * \return size of the deserialized TwoDLocation
 */
size_t deserialize(InputArchive&, TwoDLocation&);

/**
 * \brief Deserializes a ThreeDLocation from a binary archive
 * \param ar with a serialized ThreeDLocation at the beginning
 * \param loc to deserialize
 * \return size of the deserialized ThreeDLocation
 */
size_t deserialize(InputArchive&, ThreeDLocation&);

/**
 * \brief Deserializes a CircularRegion from a binary archive
 * \param ar with a serialized CiruclarRegion at the beginning
 * \param reg to deserialize
 * \return size of the deserialized CiruclarRegion
 */
size_t deserialize(InputArchive&, CircularRegion&);

/**
 * \brief Deserializes a list of RectangularRegions from a binary archive
 * \param ar with a serialized RectangularRegion list at the beginning
 * \param list to deserialize
 * \return size of the deserialized list
 */
size_t deserialize(InputArchive&, std::list<RectangularRegion>&);

/**
 * \brief Deserializes a PolygonalRegion from a binary archive
 * \param ar with a serialized PolygonalRegion at the beginning
 * \param reg to deserialize
 * \return size of the deserialized PolygonalRegion
 */
size_t deserialize(InputArchive&, PolygonalRegion&);

/**
 * \brief Deserializes an IdentifiedRegion from a binary archive
 * \param ar with a serialized IdentifiedRegion at the beginning
 * \param reg to deserialize
 * \return size of the deserialized IdentifiedRegion
 */
size_t deserialize(InputArchive&, IdentifiedRegion&);

/**
 * \brief Deserializes a GeographicRegion from a binary archive
 * \param ar with a serialized GeographicRegion at the beginning
 * \param reg to deserialize
 * \return size of the deserialized GeographicRegion
 */
size_t deserialize(InputArchive&, GeographicRegion&);

/**
 * \brief Check if position is within geographic region
 * \param pos position
 * \param r region
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const GeographicRegion&);

/**
 * \brief Check if position is within circular region
 * \param pos position
 * \param c cicrular region
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const CircularRegion&);

/**
 * \brief Check if position is within set of rectangular regions
 * \param pos position
 * \param r rectangular regions
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const std::list<RectangularRegion>&);

/**
 * \brief Check if position is within rectangular region
 * \param pos position
 * \param r rectangular region
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const RectangularRegion&);

/**
 * \brief Check if position is within polygonal region
 * \param pos position
 * \param c cicrular region
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const PolygonalRegion&);

/**
 * \brief Check if position is within identified region
 * \param pos position
 * \param i identified region
 * \true if pos is within region
 */
bool is_within(const TwoDLocation&, const IdentifiedRegion&);

/**
 * \brief Check if a region is within another geographic region
 * \param reg region
 * \param r region
 * \true if pos is within region
 */
bool is_within(const GeographicRegion&, const GeographicRegion&);

/**
 * \brief Check if a region is within a circular region
 * \param reg region
 * \param c cicrular region
 * \true if pos is within region
 */
bool is_within(const GeographicRegion&, const CircularRegion&);

/**
 * \brief Check if a region is within a set of rectangular regions
 * \param reg region
 * \param r rectangular regions
 * \true if pos is within region
 */
bool is_within(const GeographicRegion&, const std::list<RectangularRegion>&);

/**
 * \brief Check if a region is within a polygonal region
 * \param reg region
 * \param c cicrular region
 * \true if pos is within region
 */
bool is_within(const GeographicRegion&, const PolygonalRegion&);

/**
 * \brief Check if a region is within an identified region
 * \param reg region
 * \param i identified region
 * \true if pos is within region
 */
bool is_within(const GeographicRegion&, const IdentifiedRegion&);

/**
 * \brief Convert WGS84 altitude to elevation
 * \see TS 103 097 v1.2.1, section 4.2.19
 * \param altitude altitude above ellipsoid (accepts NaN)
 * \return encoded elevation
 */
ThreeDLocation::Elevation to_elevation(units::Length);

} //namespace security
} //namespace vanetza

#endif /* REGION_HPP_NUISLPMU */
