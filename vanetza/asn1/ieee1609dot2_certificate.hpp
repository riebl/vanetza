#ifndef Ieee1609Dot2Certificate_HPP_WXYNEKFN
#define Ieee1609Dot2Certificate_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/Certificate.h>


namespace vanetza
{
namespace asn1
{

class Ieee1609Dot2Certificate : public asn1c_oer_wrapper<Certificate_t>
{
public:
    using wrapper = asn1c_oer_wrapper<Certificate_t>;
    Ieee1609Dot2Certificate() : wrapper(asn_DEF_Certificate) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* Ieee1609Dot2Certificate_HPP_WXYNEKFN */
