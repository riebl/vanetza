#include <vanetza/asn1/type_traits.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>

namespace vanetza
{
namespace asn1
{

void reset(const asn_TYPE_descriptor_t& td, void* ptr)
{
    ASN_STRUCT_RESET(td, ptr);
}

asn_TYPE_descriptor_t& asn1_type_traits<OCTET_STRING_t>::descriptor()
{
    return asn_DEF_OCTET_STRING;
}

} // namespace asn1
} // namespace vanetza
