#include "header_type.hpp"
#include "areas.hpp"
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

struct gbc_header_type_visitor : public boost::static_visitor<HeaderType>
{
    HeaderType operator()(const Circle&) const
    {
        return HeaderType::GeoBroadcast_Circle;
    }

    HeaderType operator()(const Rectangle&) const
    {
        return HeaderType::GeoBroadcast_Rect;
    }

    HeaderType operator()(const Ellipse&) const
    {
        return HeaderType::GeoBroadcast_Elip;
    }
};

HeaderType gbc_header_type(const Area& area)
{
    return boost::apply_visitor(gbc_header_type_visitor(), area.shape);
}

struct gac_header_type_visitor : public boost::static_visitor<HeaderType>
{
    HeaderType operator()(const Circle&) const
    {
        return HeaderType::GeoAnycast_Circle;
    }

    HeaderType operator()(const Rectangle&) const
    {
        return HeaderType::GeoAnycast_Rect;
    }

    HeaderType operator()(const Ellipse&) const
    {
        return HeaderType::GeoAnycast_Elip;
    }
};

HeaderType gac_header_type(const Area& area)
{
    return boost::apply_visitor(gac_header_type_visitor(), area.shape);
}

} // namespace geonet
} // namespace vanetza

