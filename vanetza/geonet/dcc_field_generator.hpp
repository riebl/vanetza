#ifndef DCC_FIELD_GENERATOR_HPP_FVGALNWN
#define DCC_FIELD_GENERATOR_HPP_FVGALNWN

#include <vanetza/geonet/dcc_field.hpp>

namespace vanetza
{
namespace geonet
{

class DccFieldGenerator
{
public:
    virtual DccField generate_dcc_field() = 0;

    virtual ~DccFieldGenerator() = default;
};

class NullDccFieldGenerator : public DccFieldGenerator
{
public:
    DccField generate_dcc_field() override { return static_cast<uint32_t>(0); }
};

} // namespace geonet
} // namespace vanetza

#endif /* DCC_DCC_FIELD_GENERATOR_HPP_FVGALNWN */

