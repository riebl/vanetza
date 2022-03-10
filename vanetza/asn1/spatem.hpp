#ifndef SPATEM_HPP_XAA1ARFI
#define SPATEM_HPP_XAA1ARFI

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/SPATEM.h>

namespace vanetza
{
namespace asn1
{

class Spatem : public asn1c_per_wrapper<SPATEM_t>
{
public:
    using wrapper = asn1c_per_wrapper<SPATEM_t>;
    Spatem() : wrapper(asn_DEF_SPATEM) {}
};

} // namespace asn1
} // namespace vanetza

#endif //SPATEM_HPP_XAA1ARFI