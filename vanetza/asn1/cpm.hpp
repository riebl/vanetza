#ifndef CPM_HPP_WEWZK69S
#define CPM_HPP_WEWZK69S

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/CPM.h>

namespace vanetza
{
namespace asn1
{

class Cpm : public asn1c_per_wrapper<CPM_t>
{
public:
    Cpm() : asn1c_per_wrapper(asn_DEF_CPM) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* CPM_HPP_WEWZK69S */

