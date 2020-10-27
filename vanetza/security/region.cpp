#include <vanetza/common/serialization.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>
#include <boost/algorithm/clamp.hpp>
#include <boost/units/cmath.hpp>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <GeographicLib/Geodesic.hpp>
#include <cmath>

namespace vanetza
{
namespace security
{

const ThreeDLocation::Elevation ThreeDLocation::unknown_elevation {{ 0xF0, 0x00 }};
const ThreeDLocation::Elevation ThreeDLocation::min_elevation {{ 0xF0, 0x01 }};
const ThreeDLocation::Elevation ThreeDLocation::max_elevation {{ 0xEF, 0xFF }};

RegionType get_type(const GeographicRegion& reg)
{
    struct geograpical_region_visitor : public boost::static_visitor<RegionType>
    {
        RegionType operator()(NoneRegion reg)
        {
            return RegionType::None;
        }
        RegionType operator()(CircularRegion reg)
        {
            return RegionType::Circle;
        }
        RegionType operator()(std::list<RectangularRegion> reg)
        {
            return RegionType::Rectangle;
        }
        RegionType operator()(PolygonalRegion reg)
        {
            return RegionType::Polygon;
        }
        RegionType operator()(IdentifiedRegion reg)
        {
            return RegionType::ID;
        }
    };

    geograpical_region_visitor visit;
    return boost::apply_visitor(visit, reg);
}

bool TwoDLocation::operator==(const TwoDLocation& other) const
{
    return this->latitude == other.latitude && this->longitude == other.longitude;
}

bool TwoDLocation::operator!=(const TwoDLocation& other) const
{
    return !(*this == other);
}

bool ThreeDLocation::operator==(const ThreeDLocation& other) const
{
    return this->latitude == other.latitude && this->longitude == other.longitude && this->elevation == other.elevation;
}

bool ThreeDLocation::operator!=(const ThreeDLocation& other) const
{
    return !(*this == other);
}

bool NoneRegion::operator==(const NoneRegion& other) const
{
    return true;
}

bool NoneRegion::operator!=(const NoneRegion& other) const
{
    return !(*this == other);
}

bool CircularRegion::operator==(const CircularRegion& other) const
{
    return this->center == other.center && this->radius == other.radius;
}

bool CircularRegion::operator!=(const CircularRegion& other) const
{
    return !(*this == other);
}

bool RectangularRegion::operator==(const RectangularRegion& other) const
{
    return this->northwest == other.northwest && this->southeast == other.southeast;
}

bool RectangularRegion::operator!=(const RectangularRegion& other) const
{
    return !(*this == other);
}

bool IdentifiedRegion::operator==(const IdentifiedRegion& other) const
{
    return this->region_dictionary == other.region_dictionary
        && this->region_identifier == other.region_identifier
        && this->local_region == other.local_region;
}

bool IdentifiedRegion::operator!=(const IdentifiedRegion& other) const
{
    return !(*this == other);
}

size_t get_size(const TwoDLocation& loc)
{
    size_t size = 0;
    size += sizeof(loc.latitude);
    size += sizeof(loc.longitude);
    return size;
}

size_t get_size(const ThreeDLocation& loc)
{
    size_t size = 0;
    size += sizeof(loc.latitude);
    size += sizeof(loc.longitude);
    size += loc.elevation.size();
    return size;
}

size_t get_size(const CircularRegion& reg)
{
    size_t size = 0;
    size += get_size(reg.center);
    size += sizeof(reg.radius);
    return size;
}

size_t get_size(const RectangularRegion& reg)
{
    size_t size = 0;
    size += get_size(reg.northwest);
    size += get_size(reg.southeast);
    return size;
}

size_t get_size(const std::list<CircularRegion>& list)
{
    size_t size = 0;
    for (auto& circularRegion : list) {
        size += get_size(circularRegion.center);
        size += sizeof(circularRegion.radius);
    }
    return size;
}

size_t get_size(const std::list<RectangularRegion>& list)
{
    size_t size = 0;
    for (auto& rectangularRegion : list) {
        size += get_size(rectangularRegion.northwest);
        size += get_size(rectangularRegion.southeast);
    }
    return size;
}

size_t get_size(const PolygonalRegion& reg)
{
    size_t size = 0;
    for (auto& twoDLocation : reg) {
        size += sizeof(twoDLocation.latitude);
        size += sizeof(twoDLocation.longitude);
    }
    return size;
}

size_t get_size(const IdentifiedRegion& reg)
{
    size_t size = 0;
    size += sizeof(reg.region_dictionary);
    size += sizeof(reg.region_identifier);
    size += get_size(reg.local_region);
    return size;
}

size_t get_size(const GeographicRegion& reg)
{
    size_t size = sizeof(RegionType);

    struct geograpical_region_visitor : public boost::static_visitor<>
    {
        void operator()(NoneRegion reg)
        {
            m_size = 0;
        }
        void operator()(CircularRegion reg)
        {
            m_size = get_size(reg);
        }
        void operator()(std::list<RectangularRegion> reg)
        {
            m_size = get_size(reg);
            m_size += length_coding_size(m_size);
        }
        void operator()(PolygonalRegion reg)
        {
            m_size = get_size(reg);
            m_size += length_coding_size(m_size);
        }
        void operator()(IdentifiedRegion reg)
        {
            m_size = get_size(reg);
        }
        size_t m_size;
    };

    geograpical_region_visitor visit;
    boost::apply_visitor(visit, reg);
    size += visit.m_size;
    return size;
}

void serialize(OutputArchive& ar, const TwoDLocation& loc)
{
    serialize(ar, loc.latitude);
    serialize(ar, loc.longitude);
}

void serialize(OutputArchive& ar, const ThreeDLocation& loc)
{
    serialize(ar, loc.latitude);
    serialize(ar, loc.longitude);
    ar << loc.elevation[0];
    ar << loc.elevation[1];
}

void serialize(OutputArchive& ar, const CircularRegion& reg)
{
    serialize(ar, reg.center);
    serialize(ar, reg.radius);
}

void serialize(OutputArchive& ar, const RectangularRegion& reg)
{
    serialize(ar, reg.northwest);
    serialize(ar, reg.southeast);
}

void serialize(OutputArchive& ar, const std::list<RectangularRegion>& list)
{
    size_t size;
    size = get_size(list);
    serialize_length(ar, size);
    for (auto& rectangularRegion : list) {
        serialize(ar, rectangularRegion);
    }
}

void serialize(OutputArchive& ar, const PolygonalRegion& reg)
{
    size_t size;
    size = get_size(reg);
    serialize_length(ar, size);
    for (auto& twoDLocation : reg) {
        serialize(ar, twoDLocation);
    }
}

void serialize(OutputArchive& ar, const IdentifiedRegion& reg)
{
    serialize(ar, reg.region_dictionary);
    serialize(ar, host_cast(reg.region_identifier));
    serialize(ar, reg.local_region);
}

void serialize(OutputArchive& ar, const GeographicRegion& reg)
{
    struct geograpical_region_visitor : public boost::static_visitor<>
    {
        geograpical_region_visitor(OutputArchive& ar) :
            m_archive(ar)
        {
        }
        void operator()(NoneRegion reg)
        {
            // nothing to do
        }
        void operator()(CircularRegion reg)
        {
            serialize(m_archive, reg);
        }
        void operator()(std::list<RectangularRegion> reg)
        {
            serialize(m_archive, reg);
        }
        void operator()(PolygonalRegion reg)
        {
            serialize(m_archive, reg);
        }
        void operator()(IdentifiedRegion reg)
        {
            serialize(m_archive, reg);
        }
        OutputArchive& m_archive;
    };

    RegionType type = get_type(reg);
    serialize(ar, type);
    geograpical_region_visitor visit(ar);
    boost::apply_visitor(visit, reg);
}

size_t deserialize(InputArchive& ar, TwoDLocation& loc)
{
    deserialize(ar, loc.latitude);
    deserialize(ar, loc.longitude);
    return get_size(loc);
}

size_t deserialize(InputArchive& ar, ThreeDLocation& loc)
{
    deserialize(ar, loc.latitude);
    deserialize(ar, loc.longitude);
    ar >> loc.elevation[0];
    ar >> loc.elevation[1];
    return get_size(loc);
}

size_t deserialize(InputArchive& ar, CircularRegion& reg)
{
    size_t size = 0;
    size += deserialize(ar, reg.center);
    deserialize(ar, reg.radius);
    size += sizeof(reg.radius);
    return size;
}

size_t deserialize(InputArchive& ar, std::list<RectangularRegion>& list)
{
    size_t size, ret_size;
    size = deserialize_length(ar);
    ret_size = size;
    while (size > 0) {
        RectangularRegion reg;
        size -= deserialize(ar, reg.northwest);
        size -= deserialize(ar, reg.southeast);
        list.push_back(reg);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, PolygonalRegion& reg)
{
    size_t size, ret_size;
    size = deserialize_length(ar);
    ret_size = size;
    while (size > 0) {
        TwoDLocation loc;
        size -= deserialize(ar, loc);
        reg.push_back(loc);
    }
    return ret_size;
}

size_t deserialize(InputArchive& ar, IdentifiedRegion& reg)
{
    size_t size = 0;
    deserialize(ar, reg.region_dictionary);
    size += sizeof(RegionDictionary);
    deserialize(ar, reg.region_identifier);
    size += sizeof(reg.region_identifier);
    deserialize(ar, reg.local_region);
    size += get_size(reg.local_region);
    return size;
}

size_t deserialize(InputArchive& ar, GeographicRegion& reg)
{
    RegionType type;
    deserialize(ar, type);
    size_t size = sizeof(RegionType);
    switch (type) {
        case RegionType::None:
            NoneRegion none;
            reg = none;
            break;
        case RegionType::Circle: {
            CircularRegion circle;
            size += deserialize(ar, circle);
            reg = circle;
            break;
        }
        case RegionType::Rectangle: {
            std::list<RectangularRegion> list;
            size += deserialize(ar, list);
            size += length_coding_size(size);
            reg = list;
            break;
        }
        case RegionType::Polygon: {
            PolygonalRegion polygon;
            size += deserialize(ar, polygon);
            size += length_coding_size(size);
            reg = polygon;
            break;
        }
        case RegionType::ID: {
            IdentifiedRegion id;
            size += deserialize(ar, id);
            reg = id;
            break;
        }
        default: {
            throw deserialization_error("Unknown RegionType");
            break;
        }
    }
    return (size);
}

bool is_within(const TwoDLocation& position, const GeographicRegion& reg)
{
    struct geograpical_region_visitor : public boost::static_visitor<bool>
    {
        geograpical_region_visitor(const TwoDLocation& position) :
            m_position(position)
        {
        }
        bool operator()(const NoneRegion& reg)
        {
            return true;
        }
        bool operator()(const CircularRegion& reg)
        {
            return is_within(m_position, reg);
        }
        bool operator()(const std::list<RectangularRegion>& reg)
        {
            return is_within(m_position, reg);
        }
        bool operator()(const PolygonalRegion& reg)
        {
            return is_within(m_position, reg);
        }
        bool operator()(const IdentifiedRegion& reg)
        {
            return is_within(m_position, reg);
        }
        const TwoDLocation& m_position;
    };

    geograpical_region_visitor visit(position);
    return boost::apply_visitor(visit, reg);
}

bool is_within(const TwoDLocation& position, const CircularRegion& circular)
{
    const auto& geod = GeographicLib::Geodesic::WGS84();
    double dist = 0.0;
    const units::GeoAngle pos_lat { position.latitude };
    const units::GeoAngle pos_lon { position.longitude };
    const units::GeoAngle center_lat { circular.center.latitude };
    const units::GeoAngle center_lon { circular.center.longitude };
    geod.Inverse(pos_lat / units::degree, pos_lon / units::degree,
            center_lat / units::degree, center_lon / units::degree, dist);
    return dist <= circular.radius / units::si::meter;
}

bool is_within(const TwoDLocation& position, const std::list<RectangularRegion>& rectangles)
{
    static const unsigned max_rectangles = 6; /*< see TS 103 097 v1.2.1, section 4.2.20 */

    if (rectangles.size() > max_rectangles) {
        return false;
    }

    return std::any_of(rectangles.begin(), rectangles.end(),
            [&position](const RectangularRegion& rect) { return is_within(position, rect); });
}

bool is_within(const TwoDLocation& position, const RectangularRegion& rectangle)
{
    // basic coordinate checks according to TS 103 097 v1.2.1, 4.2.23 and IEEE 1609.2-2016, 6.4.20
    // - northwest is truly north of southeast (never equal)
    // - northwest is truly west of southeast (never equal)
    if (rectangle.northwest.latitude <= rectangle.southeast.latitude) {
        return false;
    } else if (rectangle.northwest.longitude >= rectangle.southeast.longitude) {
        return false;
    }

    if (rectangle.northwest.latitude < position.latitude) {
        return false; // position is north of rectangle
    } else if (rectangle.northwest.longitude > position.longitude) {
        return false; // position is west of rectangle
    } else if (rectangle.southeast.latitude > position.latitude) {
        return false; // position is south of rectangle
    } else if (rectangle.southeast.longitude < position.longitude) {
        return false; // position is east of rectangle
    }

    return true;
}

bool is_within(const TwoDLocation& position, const PolygonalRegion& region)
{
    // TODO: Add support for polygonal region, see TS 103 097 v1.2.1, section 4.2.24
    return false;
}

bool is_within(const TwoDLocation& position, const IdentifiedRegion& region)
{
    // TODO: Add support for identified region, see TS 103 097 v1.2.1, section 4.2.25
    return false;
}

bool is_within(const GeographicRegion& inner, const GeographicRegion& outer)
{
    struct outer_geograpical_region_visitor : public boost::static_visitor<bool>
    {
        outer_geograpical_region_visitor(const GeographicRegion& inner) :
            inner(inner)
        {
        }
        bool operator()(const NoneRegion& outer)
        {
            return true;
        }
        bool operator()(const CircularRegion& outer)
        {
            return is_within(inner, outer);
        }
        bool operator()(const std::list<RectangularRegion>& outer)
        {
            return is_within(inner, outer);
        }
        bool operator()(const PolygonalRegion& outer)
        {
            return is_within(inner, outer);
        }
        bool operator()(const IdentifiedRegion& outer)
        {
            return is_within(inner, outer);
        }
        const GeographicRegion& inner;
    };

    outer_geograpical_region_visitor visit(inner);
    return boost::apply_visitor(visit, outer);
}

bool is_within(const GeographicRegion& inner, const CircularRegion& outer)
{
    struct inner_geograpical_region_visitor : public boost::static_visitor<bool>
    {
        inner_geograpical_region_visitor(const CircularRegion& outer) :
            outer(outer)
        {
        }
        bool operator()(const NoneRegion& inner)
        {
            return false;
        }
        bool operator()(const CircularRegion& inner)
        {
            if (inner == outer) {
                return true;
            }

            const auto& geod = GeographicLib::Geodesic::WGS84();
            double center_dist = 0.0;
            const units::GeoAngle inner_lat { inner.center.latitude };
            const units::GeoAngle inner_long { inner.center.longitude };
            const units::GeoAngle outer_lat { outer.center.latitude };
            const units::GeoAngle outer_long { outer.center.longitude };
            geod.Inverse(inner_lat / units::degree, inner_long / units::degree,
                    outer_lat / units::degree, outer_long / units::degree, center_dist);
            return center_dist + inner.radius / units::si::meter <= outer.radius / units::si::meter;
        }
        bool operator()(const std::list<RectangularRegion>& inner)
        {
            // TODO: Implement check whether reactangles are within the circle
            /* Note: The rectangles can be converted to a polygon and its implementation be reused then.
             * Note: Checking whether all corners of a rectangle are within the circle is NOT enough!
             * Example: The rectangle here is spanning the earth except for a small part within the circle.
             *         ________
             *       /         \
             * _____/__       __\_____
             *     |   |     |   |
             * _____\__|     |__/____
             *       \_________/
             */
            return false;
        }
        bool operator()(const PolygonalRegion& inner)
        {
            // TODO: Implement check whether a polygon is within the circle.
            // Note: Same thoughts as for rectangles applies.
            return false;
        }
        bool operator()(const IdentifiedRegion& inner)
        {
            // TODO: Implement check whether an identified region is within the circle.
            // Note: The identified region can be converted to a polygon and its implementation be reused then.
            // Note: Same thoughts as for rectangles applies.
            return false;
        }
        const CircularRegion& outer;
    };

    inner_geograpical_region_visitor visit(outer);
    return boost::apply_visitor(visit, inner);
}

bool is_within(const GeographicRegion& inner, const std::list<RectangularRegion>& outer)
{
    // Note: The rectangles cover an area combined, there's no need for the inner shape to be within a single one!
    // TODO: Implement check whether inner is within the set of rectangles
    // Note: The rectangles can be converted to a polygon and its implementation be reused then.
    // Note: Only exact matches are implemented for now.

    struct inner_geograpical_region_visitor : public boost::static_visitor<bool>
    {
        inner_geograpical_region_visitor(const std::list<RectangularRegion>& outer) :
            outer(outer)
        {
        }
        bool operator()(const NoneRegion& inner)
        {
            return false;
        }
        bool operator()(const CircularRegion& inner)
        {
            // TODO: Implement.
            return false;
        }
        bool operator()(const std::list<RectangularRegion>& inner)
        {
            if (inner == outer) {
                return true;
            }

            // TODO: Implement.
            return false;
        }
        bool operator()(const PolygonalRegion& inner)
        {
            // TODO: Implement.
            return false;
        }
        bool operator()(const IdentifiedRegion& inner)
        {
            // TODO: Implement.
            return false;
        }
        const std::list<RectangularRegion>& outer;
    };

    inner_geograpical_region_visitor visit(outer);
    return boost::apply_visitor(visit, inner);
}

bool is_within(const GeographicRegion& inner, const PolygonalRegion& outer)
{
    // TODO: Implement check whether inner is within the polygon
    return false;
}

bool is_within(const GeographicRegion& inner, const IdentifiedRegion& outer)
{
    // TODO: Implement check whether inner is within the polygon identified by the outer region
    // Note: The identified region can be converted to a polygon and its implementation be reused then.
    return false;
}

ThreeDLocation::Elevation to_elevation(units::Length altitude)
{
    using boost::units::isnan;

    // Default to special value for NaN elevation
    ThreeDLocation::Elevation elevation { ThreeDLocation::unknown_elevation };

    if (!isnan(altitude)) {
        using boost::algorithm::clamp;

        // see TS 103 097 v1.2.1, section 4.2.19
        double altitude_dm = std::round(10.0 * (altitude / vanetza::units::si::meter));
        if (altitude_dm >= 0.0) {
            altitude_dm = clamp(altitude_dm, 0.0, 61439.0);
            auto altitude_int = static_cast<std::uint16_t>(altitude_dm);
            elevation[0] = altitude_int >> 8;
            elevation[1] = altitude_int & 0xFF;
        } else {
            altitude_dm = clamp(altitude_dm, -4095.0, -1.0);
            auto altitude_int = static_cast<std::int16_t>(altitude_dm);
            elevation[0] = altitude_int >> 8 | 0xF0;
            elevation[1] = altitude_int & 0xFF;
        }
    }

    return elevation;
}

} // namespace security
} // namespace vanetza
