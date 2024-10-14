#pragma once

// forward declarations of base types
typedef struct OCTET_STRING OCTET_STRING_t;
typedef struct ASN__PRIMITIVE_TYPE_s INTEGER_t;
using Vanetza_Security_Uint64_t = INTEGER_t;

#define ASN1_TYPE_ALIAS(name) Vanetza_Security_ ## name ## _t
#define ASN1_TYPE_NAME(name) Vanetza_Security_ ## name

#define FWD_ALIAS(name, base) \
  using ASN1_TYPE_ALIAS(name) = ASN1_TYPE_ALIAS(base); \
  namespace vanetza { namespace security { namespace v3 { namespace asn1 { \
    using name = ::ASN1_TYPE_ALIAS(name); \
  }}}}

#define FWD_OCTET_STRING(name) \
  using ASN1_TYPE_ALIAS(name) = OCTET_STRING_t; \
  namespace vanetza { namespace security { namespace v3 { namespace asn1 { \
    using name = ::ASN1_TYPE_ALIAS(name); \
  }}}}

#define FWD_STRUCT(name) \
  typedef struct ASN1_TYPE_NAME(name) ASN1_TYPE_ALIAS(name); \
  namespace vanetza { namespace security { namespace v3 { namespace asn1 { \
    using name = ::ASN1_TYPE_ALIAS(name); \
  }}}}

#define FWD_NATIVE_INTEGER(name) \
  using ASN1_TYPE_ALIAS(name) = long; \
  namespace vanetza { namespace security { namespace v3 { namespace asn1 { \
    using name = ::ASN1_TYPE_ALIAS(name); \
  }}}}

FWD_OCTET_STRING(BitmapSsp)
FWD_OCTET_STRING(HashedId8)
FWD_OCTET_STRING(Opaque)

FWD_NATIVE_INTEGER(Latitude)
FWD_NATIVE_INTEGER(Longitude)

FWD_STRUCT(CertificateBase)
FWD_STRUCT(CircularRegion)
FWD_STRUCT(EccP256CurvePoint)
FWD_STRUCT(EccP384CurvePoint)
FWD_STRUCT(GeographicRegion)
FWD_STRUCT(HeaderInfo)
FWD_STRUCT(Ieee1609Dot2Content)
FWD_STRUCT(Ieee1609Dot2Data)
FWD_STRUCT(PsidGroupPermissions)
FWD_STRUCT(PsidSsp)
FWD_STRUCT(PsidSspRange)
FWD_STRUCT(PublicEncryptionKey)
FWD_STRUCT(PublicVerificationKey)
FWD_STRUCT(RectangularRegion)
FWD_STRUCT(SequenceOfCertificate)
FWD_STRUCT(SequenceOfHashedId3)
FWD_STRUCT(SequenceOfPsidGroupPermissions)
FWD_STRUCT(SequenceOfPsidSsp)
FWD_STRUCT(SequenceOfRectangularRegion)
FWD_STRUCT(ServiceSpecificPermissions)
FWD_STRUCT(Signature)
FWD_STRUCT(SignedData)
FWD_STRUCT(SignedDataPayload)
FWD_STRUCT(SignerIdentifier)
FWD_STRUCT(SspRange)
FWD_STRUCT(ThreeDLocation)
FWD_STRUCT(ToBeSignedData)
FWD_STRUCT(TwoDLocation)
FWD_STRUCT(ValidityPeriod)
FWD_STRUCT(VerificationKeyIndicator)

FWD_ALIAS(Certificate, CertificateBase)
FWD_ALIAS(EtsiTs103097Certificate, CertificateBase)
FWD_ALIAS(EtsiTs103097Data, Ieee1609Dot2Data)
FWD_ALIAS(Time64, Uint64)

#undef ASN1_TYPE_ALIAS
#undef ASN1_TYPE_NAME
#undef FWD_ALIAS
#undef FWD_NATIVE_INTEGER
#undef FWT_OCTET_STRING
#undef FWD_STRUCT

namespace vanetza
{
namespace asn1
{
} // namespace asn1

namespace security
{
namespace v3
{
namespace asn1
{

using namespace vanetza::asn1;

} // namespace asn1
} // namespace v3
} // namespace security
} // namespace vanetza
