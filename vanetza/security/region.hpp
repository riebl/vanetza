#ifndef REGION_HPP_NUISLPMU
#define REGION_HPP_NUISLPMU

#include <vanetza/geonet/units.hpp>
#include <vanetza/security/int_x.hpp>
#include <vanetza/security/deserialization_error.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace security
{

struct TwoDLocation
{
    geonet::geo_angle_i32t latitude;
    geonet::geo_angle_i32t longitude;
};

struct ThreeDLocation
{
    geonet::geo_angle_i32t latitude;
    geonet::geo_angle_i32t longitude;
    std::array<uint8_t, 2> elevation;
};

struct CircularRegion
{
    TwoDLocation center;
    geonet::distance_u16t radius;
};

struct RectangularRegion
{
    TwoDLocation northwest;
    TwoDLocation southeast;
};

using PolygonalRegion = std::list<TwoDLocation>;

enum class RegionDictionary : uint8_t
{
    Iso_3166_1 = 0,
    Un_Stats = 1,
};

struct IdentifiedRegion
{
    RegionDictionary region_dictionary;
    int16_t region_identifier;
    IntX local_region;
};

enum class RegionType : uint8_t
{
    None = 0,       // nothing
    Circle = 1,     // CircularRegion
    Rectangle = 2,  // std::list<RectangularRegion>
    Polygon = 3,    // PolygonalRegion
    ID = 4,         // IdentifiedRegion
};

typedef boost::variant<CircularRegion, std::list<RectangularRegion>, PolygonalRegion,
    IdentifiedRegion> GeographicRegion;

/**
 * Determines RegionTyp of a GeographicRegion
 * \param GeographicRegion
 * \return RegionType
 */
RegionType get_type(const GeographicRegion&);

/**
 * Calculates size of an object
 * \param Object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const TwoDLocation&);
size_t get_size(const ThreeDLocation&);
size_t get_size(const CircularRegion&);
size_t get_size(const RectangularRegion&);
size_t get_size(const std::list<CircularRegion>&);
size_t get_size(const std::list<RectangularRegion>&);
size_t get_size(const PolygonalRegion&);
size_t get_size(const GeographicRegion&);

/**
 * Serializes an object into a binary archive
 * \param achive to serialize in
 * \param object to serialize
 */
void serialize(OutputArchive&, const TwoDLocation&);
void serialize(OutputArchive&, const ThreeDLocation&);
void serialize(OutputArchive&, const CircularRegion&);
void serialize(OutputArchive&, const RectangularRegion&);
void serialize(OutputArchive&, const std::list<RectangularRegion>&);
void serialize(OutputArchive&, const PolygonalRegion&);
void serialize(OutputArchive&, const IdentifiedRegion&);
void serialize(OutputArchive&, const GeographicRegion&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, TwoDLocation&);
size_t deserialize(InputArchive&, ThreeDLocation&);
size_t deserialize(InputArchive&, CircularRegion&);
size_t deserialize(InputArchive&, std::list<RectangularRegion>&);
size_t deserialize(InputArchive&, PolygonalRegion&);
size_t deserialize(InputArchive&, IdentifiedRegion&);
size_t deserialize(InputArchive&, GeographicRegion&);

} //namespace security
} //namspace vanetza

#endif /* REGION_HPP_NUISLPMU */
