/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2Dot1AcaEeInterface"
 * 	found in "build.asn1/ieee/IEEE1609dot2dot1AcaEeInterface.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_AcaEeCertResponse_H_
#define	_Vanetza_Security2_AcaEeCertResponse_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Uint8.h"
#include "Time32.h"
#include "Certificate.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_Security2_AcaEeCertResponse */
typedef struct Vanetza_Security2_AcaEeCertResponse {
	Vanetza_Security2_Uint8_t	 version;
	Vanetza_Security2_Time32_t	 generationTime;
	Vanetza_Security2_Certificate_t	 certificate;
	OCTET_STRING_t	*privateKeyInfo;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_AcaEeCertResponse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_AcaEeCertResponse;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security2_AcaEeCertResponse_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_AcaEeCertResponse_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_AcaEeCertResponse_H_ */
#include "asn_internal.h"