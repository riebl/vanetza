#include "gbc_gac_header.hpp"
#include "areas.hpp"

namespace vanetza
{
namespace geonet
{
namespace detail
{

class set_distance_visitor : public boost::static_visitor<>
{
public:
    set_distance_visitor(GbcGacHeader& hdr) : m_header(hdr) {}

    void operator()(const Circle& circle)
    {
        m_header.distance_a = circle.r;
        m_header.distance_b = circle.r;
    }

    void operator()(const Rectangle& rect)
    {
        m_header.distance_a = rect.a;
        m_header.distance_b = rect.b;
    }

    void operator()(const Ellipse& elip)
    {
        m_header.distance_a = elip.a;
        m_header.distance_b = elip.b;
    }

private:
    GbcGacHeader& m_header;
};

class get_distance_visitor : public boost::static_visitor<>
{
public:
    get_distance_visitor(const GbcGacHeader& hdr) : m_header(hdr) {}

    void operator()(Circle& circle)
    {
        circle.r = m_header.distance_a;
    }

    void operator()(Rectangle& rect)
    {
        rect.a = m_header.distance_a;
        rect.b = m_header.distance_b;
    }

    void operator()(Ellipse& elip)
    {
        elip.a = m_header.distance_a;
        elip.b = m_header.distance_b;
    }

private:
    const GbcGacHeader& m_header;
};

void GbcGacHeader::destination(const Area& area)
{
    this->position(area.position);
    angle = static_cast<angle_u16t>(area.angle);
    set_distance_visitor visitor(*this);
    boost::apply_visitor(visitor, area.shape);
}

Area GbcGacHeader::destination(const decltype(Area::shape)& shape) const
{
    Area area;
    area.shape = shape;
    area.position = this->position();
    area.angle = static_cast<units::Angle>(angle);
    get_distance_visitor visitor(*this);
    boost::apply_visitor(visitor, area.shape);
    return area;
}

void GbcGacHeader::position(const GeodeticPosition& position)
{
    geo_area_pos_latitude = static_cast<geo_angle_i32t>(position.latitude);
    geo_area_pos_longitude = static_cast<geo_angle_i32t>(position.longitude);
}

GeodeticPosition GbcGacHeader::position() const
{
    return GeodeticPosition(
            static_cast<units::GeoAngle>(geo_area_pos_latitude),
            static_cast<units::GeoAngle>(geo_area_pos_longitude)
        );
}

} // namespace detail
} // namespace geonet
} // namepsace vanetza

