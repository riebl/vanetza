#ifndef EtsiTs103097Data_HPP_WXYNEKFN
#define EtsiTs103097Data_HPP_WXYNEKFN

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/security/EtsiTs103097Data.h>


namespace vanetza
{
namespace asn1
{

class EtsiTs103097Data : public asn1c_oer_wrapper<EtsiTs103097Data_t>
{
public:
    using wrapper = asn1c_oer_wrapper<EtsiTs103097Data_t>;
    EtsiTs103097Data() : wrapper(asn_DEF_EtsiTs103097Data) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* EtsiTs103097Data_HPP_WXYNEKFN */
