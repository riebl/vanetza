/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941TypesAuthorizationValidation"
 * 	found in "asn1/release2/TS102941v221/TypesAuthorizationValidation.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_AuthorizationValidationResponseCode_H_
#define	_Vanetza_Security2_AuthorizationValidationResponseCode_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security2_AuthorizationValidationResponseCode {
	Vanetza_Security2_AuthorizationValidationResponseCode_ok	= 0,
	Vanetza_Security2_AuthorizationValidationResponseCode_cantparse	= 1,
	Vanetza_Security2_AuthorizationValidationResponseCode_badcontenttype	= 2,
	Vanetza_Security2_AuthorizationValidationResponseCode_imnottherecipient	= 3,
	Vanetza_Security2_AuthorizationValidationResponseCode_unknownencryptionalgorithm	= 4,
	Vanetza_Security2_AuthorizationValidationResponseCode_decryptionfailed	= 5,
	Vanetza_Security2_AuthorizationValidationResponseCode_invalidaa	= 6,
	Vanetza_Security2_AuthorizationValidationResponseCode_invalidaasignature	= 7,
	Vanetza_Security2_AuthorizationValidationResponseCode_wrongea	= 8,
	Vanetza_Security2_AuthorizationValidationResponseCode_unknownits	= 9,
	Vanetza_Security2_AuthorizationValidationResponseCode_invalidsignature	= 10,
	Vanetza_Security2_AuthorizationValidationResponseCode_invalidencryptionkey	= 11,
	Vanetza_Security2_AuthorizationValidationResponseCode_deniedpermissions	= 12,
	Vanetza_Security2_AuthorizationValidationResponseCode_deniedtoomanycerts	= 13,
	Vanetza_Security2_AuthorizationValidationResponseCode_deniedrequest	= 14
	/*
	 * Enumeration is extensible
	 */
} e_Vanetza_Security2_AuthorizationValidationResponseCode;

/* Vanetza_Security2_AuthorizationValidationResponseCode */
typedef long	 Vanetza_Security2_AuthorizationValidationResponseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Vanetza_Security2_AuthorizationValidationResponseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_AuthorizationValidationResponseCode;
extern const asn_INTEGER_specifics_t asn_SPC_Vanetza_Security2_AuthorizationValidationResponseCode_specs_1;
asn_struct_free_f Vanetza_Security2_AuthorizationValidationResponseCode_free;
asn_struct_print_f Vanetza_Security2_AuthorizationValidationResponseCode_print;
asn_constr_check_f Vanetza_Security2_AuthorizationValidationResponseCode_constraint;
ber_type_decoder_f Vanetza_Security2_AuthorizationValidationResponseCode_decode_ber;
der_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_der;
xer_type_decoder_f Vanetza_Security2_AuthorizationValidationResponseCode_decode_xer;
xer_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_xer;
jer_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_jer;
oer_type_decoder_f Vanetza_Security2_AuthorizationValidationResponseCode_decode_oer;
oer_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_oer;
per_type_decoder_f Vanetza_Security2_AuthorizationValidationResponseCode_decode_uper;
per_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_uper;
per_type_decoder_f Vanetza_Security2_AuthorizationValidationResponseCode_decode_aper;
per_type_encoder_f Vanetza_Security2_AuthorizationValidationResponseCode_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_AuthorizationValidationResponseCode_H_ */
#include "asn_internal.h"
