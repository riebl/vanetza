#pragma once
#include <vanetza/common/byte_view.hpp>

// forward declaration of ASN.1 types
using OCTET_STRING_t = struct OCTET_STRING;

namespace vanetza
{
namespace asn1
{

/**
 * Create a byte view of an OCTET STRING's content
 * \param octets OCTET STRING
 * \return view valid as long as the content of octets is unchanged
 */
byte_view_range create_byte_view(const OCTET_STRING_t& octets);

} // namespace asn1
} // namespace vanetza
