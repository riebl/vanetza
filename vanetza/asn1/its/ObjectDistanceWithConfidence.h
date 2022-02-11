/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/TR103562v211.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ObjectDistanceWithConfidence_H_
#define	_ObjectDistanceWithConfidence_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DistanceValue.h"
#include "DistanceConfidence.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ObjectDistanceWithConfidence */
typedef struct ObjectDistanceWithConfidence {
	DistanceValue_t	 value;
	DistanceConfidence_t	 confidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ObjectDistanceWithConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ObjectDistanceWithConfidence;
extern asn_SEQUENCE_specifics_t asn_SPC_ObjectDistanceWithConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_ObjectDistanceWithConfidence_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _ObjectDistanceWithConfidence_H_ */
#include "asn_internal.h"
