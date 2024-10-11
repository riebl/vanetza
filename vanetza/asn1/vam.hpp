#ifndef VAM_HPP_RSEIP89V
#define VAM_HPP_RSEIP89V

#define VANETZA_USE_ITS2 1

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#if VANETZA_USE_ITS2
#include <vanetza/asn1/its/VAM.h>
#else
#include <vanetza/asn1/its/VruAwareness.h>
#endif

namespace vanetza
{
namespace asn1
{
#if VANETZA_USE_ITS2
class Vam : public asn1c_per_wrapper<VAM_t>
#else
class Vam : public asn1c_per_wrapper<VruAwareness_t>
#endif
{
public:
#if VANETZA_USE_ITS2
    Vam() : asn1c_per_wrapper(asn_DEF_VAM) {}
#else
    Vam() : asn1c_per_wrapper(asn_DEF_VruAwareness) {}
#endif
};

} // namespace asn1
} // namespace vanetza

#endif /* VAM_HPP_RSEIP89V */

