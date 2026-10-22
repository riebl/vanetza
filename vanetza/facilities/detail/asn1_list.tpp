#pragma once
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <stdexcept>
#include <utility>

namespace vanetza
{
namespace facilities
{
namespace detail
{

/**
 * Allocate an OPTIONAL member if not present yet
 * \param member pointer member of an asn1c struct, owned by that struct
 * \return present member
 */
template<typename T>
T* allocate_optional(T*& member)
{
    if (!member) {
        member = asn1::allocate<T>();
    }
    return member;
}

/**
 * Append an element to an asn1c SEQUENCE OF, transferring ownership on success
 * \param list asn1c list (destination)
 * \param element owned element, freed by its deleter if appending fails
 * \return appended element, now owned by list
 */
template<typename LIST, typename T>
T& append(LIST& list, std::unique_ptr<T, asn1::deleter> element)
{
    if (ASN_SEQUENCE_ADD(&list, element.get()) != 0) {
        throw std::runtime_error("ASN.1 sequence append failed");
    }
    return *element.release();
}

} // namespace detail
} // namespace facilities
} // namespace vanetza
