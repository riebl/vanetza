/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/EN302637-2v141-CAM.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_RSUContainerHighFrequency_H_
#define	_RSUContainerHighFrequency_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ProtectedCommunicationZonesRSU;

/* RSUContainerHighFrequency */
typedef struct RSUContainerHighFrequency {
	struct ProtectedCommunicationZonesRSU	*protectedCommunicationZonesRSU;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RSUContainerHighFrequency_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RSUContainerHighFrequency;
extern asn_SEQUENCE_specifics_t asn_SPC_RSUContainerHighFrequency_specs_1;
extern asn_TYPE_member_t asn_MBR_RSUContainerHighFrequency_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RSUContainerHighFrequency_H_ */
#include "asn_internal.h"
