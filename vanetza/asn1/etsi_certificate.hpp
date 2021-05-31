#ifndef EtsiTs103097Certificate_HPP_WXYNEKFN
#define EtsiTs103097Certificate_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Certificate.h>


namespace vanetza
{
namespace asn1
{

class EtsiTs103097Certificate : public asn1c_oer_wrapper<EtsiTs103097Certificate_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EtsiTs103097Certificate_t>;
    EtsiTs103097Certificate() : wrapper(asn_DEF_EtsiTs103097Certificate) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* EtsiTs103097Certificate_HPP_WXYNEKFN */
