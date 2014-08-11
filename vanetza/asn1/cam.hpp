#ifndef CAM_HPP_WXYNEKFN
#define CAM_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/gen/CAM.h>

namespace vanetza
{
namespace asn1
{

class Cam : public asn1c_wrapper<CAM_t>
{
public:
    Cam() : asn1c_wrapper(asn_DEF_CAM) {}
};

} // namespace asn1

namespace convertible
{

template<>
struct byte_buffer_impl<vanetza::asn1::Cam> :
public asn1::byte_buffer_impl<vanetza::asn1::Cam>
{
    using asn1::byte_buffer_impl<vanetza::asn1::Cam>::byte_buffer_impl;
};

} // namespace convertible
} // namespace vanetza

#endif /* CAM_HPP_WXYNEKFN */

