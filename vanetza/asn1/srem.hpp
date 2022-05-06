#ifndef SREM_HPP_AWEH4562
#define SREM_HPP_AWEH4562

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/SREM.h>

namespace vanetza
{
namespace asn1
{

class Srem : public asn1c_per_wrapper<SREM_t>
{
public:
    using wrapper = asn1c_per_wrapper<SREM_t>;
    Srem() : wrapper(asn_DEF_SREM) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* SREM_HPP_AWEH4562 */
