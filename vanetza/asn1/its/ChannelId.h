/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EfcDsrcApplication"
 * 	found in "build.asn1/iso/ISO14906-0-6.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ChannelId_H_
#define	_ChannelId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ChannelId {
	ChannelId_obu	= 0,
	ChannelId_sam1	= 1,
	ChannelId_sam2	= 2,
	ChannelId_icc	= 3,
	ChannelId_display	= 4,
	ChannelId_buzzer	= 5,
	ChannelId_printer	= 6,
	ChannelId_serialInterface	= 7,
	ChannelId_parallelInterface	= 8,
	ChannelId_gPS	= 9,
	ChannelId_tachograph	= 10,
	ChannelId_privateUse1	= 11,
	ChannelId_privateUse2	= 12,
	ChannelId_privateUse3	= 13,
	ChannelId_privateUse4	= 14,
	ChannelId_privateUse5	= 15,
	ChannelId_bluetooth	= 16
} e_ChannelId;

/* ChannelId */
typedef long	 ChannelId_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ChannelId_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ChannelId;
asn_struct_free_f ChannelId_free;
asn_struct_print_f ChannelId_print;
asn_constr_check_f ChannelId_constraint;
ber_type_decoder_f ChannelId_decode_ber;
der_type_encoder_f ChannelId_encode_der;
xer_type_decoder_f ChannelId_decode_xer;
xer_type_encoder_f ChannelId_encode_xer;
oer_type_decoder_f ChannelId_decode_oer;
oer_type_encoder_f ChannelId_encode_oer;
per_type_decoder_f ChannelId_decode_uper;
per_type_encoder_f ChannelId_encode_uper;
per_type_decoder_f ChannelId_decode_aper;
per_type_encoder_f ChannelId_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _ChannelId_H_ */
#include "asn_internal.h"
