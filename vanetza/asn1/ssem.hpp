#ifndef SSEM_HPP_DFK546SZ
#define SSEM_HPP_DFK546SZ

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/SSEM.h>

namespace vanetza
{
namespace asn1
{

class Ssem : public asn1c_per_wrapper<SSEM_t>
{
public:
    using wrapper = asn1c_per_wrapper<SSEM_t>;
    Ssem() : wrapper(asn_DEF_SSEM) {}
};

} // namespace asn1
} // namespace vanetza

#endif // SSEM_HPP_DFK546SZ
