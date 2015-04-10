#ifndef DENM_HPP_XGC8NRDI
#define DENM_HPP_XGC8NRDI

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/gen/DENM.h>

namespace vanetza
{
namespace asn1
{

class Denm : public asn1c_wrapper<DENM_t>
{
public:
    Denm() : asn1c_wrapper<DENM_t>(asn_DEF_DENM) {}
};

} // namespace asn1

namespace convertible
{

template<>
struct byte_buffer_impl<vanetza::asn1::Denm> :
public asn1::byte_buffer_impl<vanetza::asn1::Denm>
{
    using asn1::byte_buffer_impl<vanetza::asn1::Denm>::byte_buffer_impl;
};

} // namespace convertible
} // namespace vanetza

#endif /* DENM_HPP_XGC8NRDI */

