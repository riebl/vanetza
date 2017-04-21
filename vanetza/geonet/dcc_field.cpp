#include <vanetza/geonet/dcc_field.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

void serialize(const DccField& field, OutputArchive& ar)
{
    struct serialize_visitor : boost::static_visitor<uint32_t>
    {
        uint32_t operator()(const DccMcoField& mco) const { return static_cast<uint32_t>(mco); }
        uint32_t operator()(const uint32_t& raw) const { return raw; }
    };

    uint32_t raw = boost::apply_visitor(serialize_visitor {}, field);
    serialize(host_cast(raw), ar);
}

void deserialize(DccField& field, InputArchive& ar)
{
    uint32_t raw;
    deserialize(raw, ar);
    field = raw;
}

} // namespace geonet
} // namespace vanetza
