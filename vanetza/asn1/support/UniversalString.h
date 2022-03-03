/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_UniversalString_H_
#define	_UniversalString_H_

#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef OCTET_STRING_t UniversalString_t;  /* Implemented via OCTET STRING */

extern asn_TYPE_descriptor_t asn_DEF_UniversalString;
extern asn_TYPE_operation_t asn_OP_UniversalString;
extern asn_OCTET_STRING_specifics_t asn_SPC_UniversalString_specs;

#define UniversalString_free OCTET_STRING_free

#if !defined(ASN_DISABLE_PRINT_SUPPORT)
asn_struct_print_f UniversalString_print;  /* Human-readable output */
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */

#define UniversalString_compare OCTET_STRING_compare

asn_constr_check_f UniversalString_constraint;

#if !defined(ASN_DISABLE_BER_SUPPORT)
#define UniversalString_decode_ber OCTET_STRING_decode_ber
#define UniversalString_encode_der OCTET_STRING_encode_der
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */

#if !defined(ASN_DISABLE_XER_SUPPORT)
xer_type_decoder_f UniversalString_decode_xer;
xer_type_encoder_f UniversalString_encode_xer;
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */

#if !defined(ASN_DISABLE_UPER_SUPPORT)
#define UniversalString_decode_uper OCTET_STRING_decode_uper
#define UniversalString_encode_uper OCTET_STRING_encode_uper
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
#define UniversalString_decode_aper OCTET_STRING_decode_aper
#define UniversalString_encode_aper OCTET_STRING_encode_aper
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */

ssize_t UniversalString__dump(const UniversalString_t *st,
                              asn_app_consume_bytes_f *cb,
                              void *app_key);

#ifdef __cplusplus
}
#endif

#endif	/* _UniversalString_H_ */
