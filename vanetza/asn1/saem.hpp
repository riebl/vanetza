#ifndef SAEM_HPP_WXYNEKFN
#define SAEM_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/SAEM.h>
#include <vanetza/asn1/its/r2/SAEM.h>

namespace vanetza
{
namespace asn1
{

namespace r1
{

class Saem : public asn1c_per_wrapper<SAEM_t>
{
public:
    using wrapper = asn1c_per_wrapper<SAEM_t>;
    Saem() : wrapper(asn_DEF_SAEM) {}
};

} // namespace r1

namespace r2
{

class Saem : public asn1c_per_wrapper<Vanetza_ITS2_SAEM_t>
{
public:
    using wrapper = asn1c_per_wrapper<Vanetza_ITS2_SAEM_t>;
    Saem() : wrapper(asn_DEF_Vanetza_ITS2_SAEM) {}
};

} // namespace r2

// alias for backward compatibility
using Saem = r1::Saem;

} // namespace asn1
} // namespace vanetza

#endif /* CAM_HPP_WXYNEKFN */
