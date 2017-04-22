#include <vanetza/geonet/dcc_field.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

namespace vanetza
{
namespace geonet
{

struct dcc_mco_extractor : boost::static_visitor< boost::optional<DccMcoField> >
{
    using return_type = boost::optional<DccMcoField>;

    return_type operator()(const DccMcoField& mco) const
    {
        return mco;
    }

    return_type operator()(uint32_t raw) const
    {
        return DccMcoField { raw };
    }

    template<typename T>
    return_type operator()(const T&)
    {
        return boost::none;
    }
};

boost::optional<DccMcoField> get_dcc_mco(const DccField& field)
{
    return boost::apply_visitor(dcc_mco_extractor {}, field);
}

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
