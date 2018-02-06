#include <vanetza/common/serialization.hpp>
#include <vanetza/security/exception.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/units/angle.hpp>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <GeographicLib/Geodesic.hpp>

namespace vanetza
{
namespace security
{

RegionType get_type(const GeographicRegion& reg)
{
    struct geograpical_region_visitor : public boost::static_visitor<RegionType>
    {
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

} // namespace security
} // namespace vanetza
