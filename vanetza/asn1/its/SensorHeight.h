/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/TR103562v211.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_SensorHeight_H_
#define	_SensorHeight_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SensorHeight {
	SensorHeight_zeroPointZeroOneMeter	= 1
} e_SensorHeight;

/* SensorHeight */
typedef long	 SensorHeight_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_SensorHeight_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_SensorHeight;
asn_struct_free_f SensorHeight_free;
asn_struct_print_f SensorHeight_print;
asn_constr_check_f SensorHeight_constraint;
ber_type_decoder_f SensorHeight_decode_ber;
der_type_encoder_f SensorHeight_encode_der;
xer_type_decoder_f SensorHeight_decode_xer;
xer_type_encoder_f SensorHeight_encode_xer;
oer_type_decoder_f SensorHeight_decode_oer;
oer_type_encoder_f SensorHeight_encode_oer;
per_type_decoder_f SensorHeight_decode_uper;
per_type_encoder_f SensorHeight_encode_uper;
per_type_decoder_f SensorHeight_decode_aper;
per_type_encoder_f SensorHeight_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _SensorHeight_H_ */
#include "asn_internal.h"
