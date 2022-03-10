#ifndef MAPEM_HPP_ABA2ARCD
#define MAPEM_HPP_ABA2ARCD

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/MAPEM.h>

namespace vanetza
{
namespace asn1
{

class Mapem : public asn1c_per_wrapper<MAPEM_t>
{
public:
    using wrapper = asn1c_per_wrapper<MAPEM_t>;
    Mapem() : wrapper(asn_DEF_MAPEM) {}
};

} // namespace asn1
} // namespace vanetza

#endif //MAPEM_HPP_ABA2ARCD
