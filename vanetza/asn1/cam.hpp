#ifndef CAM_HPP_WXYNEKFN
#define CAM_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/CAM.h>
#include <vanetza/asn1/its/r2/CAM.h>

namespace vanetza
{
namespace asn1
{

namespace r1
{

class Cam : public asn1c_per_wrapper<CAM_t>
{
public:
    using wrapper = asn1c_per_wrapper<CAM_t>;
    Cam() : wrapper(asn_DEF_CAM) {}
};

} // namespace r1

namespace r2
{

class Cam : public asn1c_per_wrapper<Vanetza_ITS2_CAM_t>
{
public:
    using wrapper = asn1c_per_wrapper<Vanetza_ITS2_CAM_t>;
    Cam() : wrapper(asn_DEF_Vanetza_ITS2_CAM) {}
};

} // namespace r2

// alias for backward compatibility
using Cam = r1::Cam;

} // namespace asn1
} // namespace vanetza

#endif /* CAM_HPP_WXYNEKFN */
