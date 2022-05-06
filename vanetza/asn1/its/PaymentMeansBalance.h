/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EfcDsrcApplication"
 * 	found in "build.asn1/iso/ISO14906-0-6.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_PaymentMeansBalance_H_
#define	_PaymentMeansBalance_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SignedValue.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PaymentMeansBalance */
typedef SignedValue_t	 PaymentMeansBalance_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PaymentMeansBalance;
asn_struct_free_f PaymentMeansBalance_free;
asn_struct_print_f PaymentMeansBalance_print;
asn_constr_check_f PaymentMeansBalance_constraint;
ber_type_decoder_f PaymentMeansBalance_decode_ber;
der_type_encoder_f PaymentMeansBalance_encode_der;
xer_type_decoder_f PaymentMeansBalance_decode_xer;
xer_type_encoder_f PaymentMeansBalance_encode_xer;
oer_type_decoder_f PaymentMeansBalance_decode_oer;
oer_type_encoder_f PaymentMeansBalance_encode_oer;
per_type_decoder_f PaymentMeansBalance_decode_uper;
per_type_encoder_f PaymentMeansBalance_encode_uper;
per_type_decoder_f PaymentMeansBalance_decode_aper;
per_type_encoder_f PaymentMeansBalance_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _PaymentMeansBalance_H_ */
#include "asn_internal.h"
