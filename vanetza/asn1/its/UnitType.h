/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EfcDsrcApplication"
 * 	found in "build.asn1/iso/ISO14906-0-6.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_UnitType_H_
#define	_UnitType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UnitType {
	UnitType_mg_km	= 0,
	UnitType_mg_kWh	= 1
} e_UnitType;

/* UnitType */
typedef long	 UnitType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_UnitType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_UnitType;
extern const asn_INTEGER_specifics_t asn_SPC_UnitType_specs_1;
asn_struct_free_f UnitType_free;
asn_struct_print_f UnitType_print;
asn_constr_check_f UnitType_constraint;
ber_type_decoder_f UnitType_decode_ber;
der_type_encoder_f UnitType_encode_der;
xer_type_decoder_f UnitType_decode_xer;
xer_type_encoder_f UnitType_encode_xer;
oer_type_decoder_f UnitType_decode_oer;
oer_type_encoder_f UnitType_encode_oer;
per_type_decoder_f UnitType_decode_uper;
per_type_encoder_f UnitType_encode_uper;
per_type_decoder_f UnitType_decode_aper;
per_type_encoder_f UnitType_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _UnitType_H_ */
#include "asn_internal.h"
