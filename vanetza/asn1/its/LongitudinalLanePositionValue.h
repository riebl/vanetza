/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/TR103562v211.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_LongitudinalLanePositionValue_H_
#define	_LongitudinalLanePositionValue_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LongitudinalLanePositionValue {
	LongitudinalLanePositionValue_zeroPointOneMeter	= 1
} e_LongitudinalLanePositionValue;

/* LongitudinalLanePositionValue */
typedef long	 LongitudinalLanePositionValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LongitudinalLanePositionValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LongitudinalLanePositionValue;
asn_struct_free_f LongitudinalLanePositionValue_free;
asn_struct_print_f LongitudinalLanePositionValue_print;
asn_constr_check_f LongitudinalLanePositionValue_constraint;
ber_type_decoder_f LongitudinalLanePositionValue_decode_ber;
der_type_encoder_f LongitudinalLanePositionValue_encode_der;
xer_type_decoder_f LongitudinalLanePositionValue_decode_xer;
xer_type_encoder_f LongitudinalLanePositionValue_encode_xer;
oer_type_decoder_f LongitudinalLanePositionValue_decode_oer;
oer_type_encoder_f LongitudinalLanePositionValue_encode_oer;
per_type_decoder_f LongitudinalLanePositionValue_decode_uper;
per_type_encoder_f LongitudinalLanePositionValue_encode_uper;
per_type_decoder_f LongitudinalLanePositionValue_decode_aper;
per_type_encoder_f LongitudinalLanePositionValue_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _LongitudinalLanePositionValue_H_ */
#include "asn_internal.h"
