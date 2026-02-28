#pragma once
#include <vanetza/asn1/security/HashedId3.h>
#include <vanetza/asn1/security/HashedId8.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/asn1_types.hpp>


namespace vanetza
{
namespace security
{

HashedId8 create_hashed_id8(const Vanetza_Security_HashedId8_t&);
HashedId3 create_hashed_id3(const Vanetza_Security_HashedId3_t&);

namespace v3
{

HashedId8 convert(const Vanetza_Security_HashedId8_t&);

/**
 * Assign ByteBuffer content to an ASN.1 OCTET_STRING
 * \param dst destination OCTET_STRING
 * \param src source byte buffer
 */
void assign(OCTET_STRING_t* dst, const ByteBuffer& src);

/**
 * Convert an EccPoint to its ASN.1 EccP256CurvePoint representation
 * \param point ECC point to convert
 * \return ASN.1 EccP256CurvePoint
 */
asn1::EccP256CurvePoint to_asn1(const EccPoint& point);

} // namespace v3
} // namespace security
} // namespace vanetza
