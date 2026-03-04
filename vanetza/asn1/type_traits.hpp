#pragma once

// forward declaration of ASN.1 types
using OCTET_STRING_t = struct OCTET_STRING;
using asn_TYPE_descriptor_t = struct asn_TYPE_descriptor_s;

namespace vanetza
{
namespace asn1
{

template<typename T>
struct asn1_type_traits;

template<> struct asn1_type_traits<OCTET_STRING>
{
    static asn_TYPE_descriptor_t& descriptor();
};

void reset(const asn_TYPE_descriptor_t& td, void* ptr);

template<typename T>
void reset(T& value)
{
    reset(asn1_type_traits<T>::descriptor(), &value);
}

template<typename T>
void reset(T* ptr)
{
    reset(asn1_type_traits<T>::descriptor(), ptr);
}

} // namespace asn1
} // namespace vanetza
