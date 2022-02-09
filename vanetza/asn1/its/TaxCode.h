/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "AVIAEINumberingAndDataStructures"
 * 	found in "asn1/ISO14816_AVIAEINumberingAndDataStructures.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_TaxCode_H_
#define	_TaxCode_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TaxCode */
typedef OCTET_STRING_t	 TaxCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TaxCode;
asn_struct_free_f TaxCode_free;
asn_struct_print_f TaxCode_print;
asn_constr_check_f TaxCode_constraint;
ber_type_decoder_f TaxCode_decode_ber;
der_type_encoder_f TaxCode_encode_der;
xer_type_decoder_f TaxCode_decode_xer;
xer_type_encoder_f TaxCode_encode_xer;
oer_type_decoder_f TaxCode_decode_oer;
oer_type_encoder_f TaxCode_encode_oer;
per_type_decoder_f TaxCode_decode_uper;
per_type_encoder_f TaxCode_encode_uper;
per_type_decoder_f TaxCode_decode_aper;
per_type_encoder_f TaxCode_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _TaxCode_H_ */
#include "asn_internal.h"
