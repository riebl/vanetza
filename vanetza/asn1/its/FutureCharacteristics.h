/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EfcDsrcApplication"
 * 	found in "build.asn1/iso/ISO14906-0-6.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_FutureCharacteristics_H_
#define	_FutureCharacteristics_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum FutureCharacteristics {
	FutureCharacteristics_noEntry	= 0,
	FutureCharacteristics_airSuspension	= 1
} e_FutureCharacteristics;

/* FutureCharacteristics */
typedef long	 FutureCharacteristics_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_FutureCharacteristics_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_FutureCharacteristics;
asn_struct_free_f FutureCharacteristics_free;
asn_struct_print_f FutureCharacteristics_print;
asn_constr_check_f FutureCharacteristics_constraint;
ber_type_decoder_f FutureCharacteristics_decode_ber;
der_type_encoder_f FutureCharacteristics_encode_der;
xer_type_decoder_f FutureCharacteristics_decode_xer;
xer_type_encoder_f FutureCharacteristics_encode_xer;
oer_type_decoder_f FutureCharacteristics_decode_oer;
oer_type_encoder_f FutureCharacteristics_encode_oer;
per_type_decoder_f FutureCharacteristics_decode_uper;
per_type_encoder_f FutureCharacteristics_encode_uper;
per_type_decoder_f FutureCharacteristics_decode_aper;
per_type_encoder_f FutureCharacteristics_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _FutureCharacteristics_H_ */
#include "asn_internal.h"