/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/ISO-TS-19091-addgrp-C-2018-patched.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_AdvisorySpeedType_H_
#define	_AdvisorySpeedType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AdvisorySpeedType {
	AdvisorySpeedType_none	= 0,
	AdvisorySpeedType_greenwave	= 1,
	AdvisorySpeedType_ecoDrive	= 2,
	AdvisorySpeedType_transit	= 3
	/*
	 * Enumeration is extensible
	 */
} e_AdvisorySpeedType;

/* AdvisorySpeedType */
typedef long	 AdvisorySpeedType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AdvisorySpeedType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AdvisorySpeedType;
extern const asn_INTEGER_specifics_t asn_SPC_AdvisorySpeedType_specs_1;
asn_struct_free_f AdvisorySpeedType_free;
asn_struct_print_f AdvisorySpeedType_print;
asn_constr_check_f AdvisorySpeedType_constraint;
ber_type_decoder_f AdvisorySpeedType_decode_ber;
der_type_encoder_f AdvisorySpeedType_encode_der;
xer_type_decoder_f AdvisorySpeedType_decode_xer;
xer_type_encoder_f AdvisorySpeedType_encode_xer;
oer_type_decoder_f AdvisorySpeedType_decode_oer;
oer_type_encoder_f AdvisorySpeedType_encode_oer;
per_type_decoder_f AdvisorySpeedType_decode_uper;
per_type_encoder_f AdvisorySpeedType_encode_uper;
per_type_decoder_f AdvisorySpeedType_decode_aper;
per_type_encoder_f AdvisorySpeedType_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _AdvisorySpeedType_H_ */
#include "asn_internal.h"
