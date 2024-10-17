#ifndef CPM_HPP_WEWZK69S
#define CPM_HPP_WEWZK69S

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/CPM.h>
#include <vanetza/asn1/its/r2/CollectivePerceptionMessage.h>

namespace vanetza
{
namespace asn1
{

namespace r1
{

class Cpm : public asn1c_per_wrapper<CPM_t>
{
public:
    Cpm() : asn1c_per_wrapper(asn_DEF_CPM) {}
};

} // namespace r1

namespace r2
{

class Cpm : public asn1c_per_wrapper<Vanetza_ITS2_CollectivePerceptionMessage_t>
{
public:
    Cpm() : asn1c_per_wrapper(asn_DEF_Vanetza_ITS2_CollectivePerceptionMessage) {}
};

} // namespace r2

// alias for backward compatibility
using Cpm = r1::Cpm;

} // namespace asn1
} // namespace vanetza

#endif /* CPM_HPP_WEWZK69S */
