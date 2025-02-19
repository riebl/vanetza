#ifndef VAM_HPP_RSEIP89V
#define VAM_HPP_RSEIP89V

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/r2/VAM.h>

namespace vanetza
{
namespace asn1
{


namespace r2
{

class Vam : public asn1c_per_wrapper<Vanetza_ITS2_VAM_t>
{
public:
    Vam() : asn1c_per_wrapper(asn_DEF_Vanetza_ITS2_VAM) {}
};

} // namespace r2


} // namespace asn1
} // namespace vanetza

#endif /* VAM_HPP_RSEIP89V */
