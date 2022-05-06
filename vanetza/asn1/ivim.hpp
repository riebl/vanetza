#ifndef IVIM_HPP_D5N8Q2JO
#define IVIM_HPP_D5N8Q2JO

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/IVIM.h>

namespace vanetza
{
namespace asn1
{

class Ivim : public asn1c_per_wrapper<IVIM_t>
{
public:
    using wrapper = asn1c_per_wrapper<IVIM_t>;
    Ivim() : wrapper(asn_DEF_IVIM) {}
};

} // namespace asn1
} // namespace vanetza

#endif // IVIM_HPP_D5N8Q2JO
