/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/TS102894-2v131-CDD.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_DeltaReferencePosition_H_
#define	_DeltaReferencePosition_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DeltaLatitude.h"
#include "DeltaLongitude.h"
#include "DeltaAltitude.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DeltaReferencePosition */
typedef struct DeltaReferencePosition {
	DeltaLatitude_t	 deltaLatitude;
	DeltaLongitude_t	 deltaLongitude;
	DeltaAltitude_t	 deltaAltitude;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DeltaReferencePosition_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DeltaReferencePosition;
extern asn_SEQUENCE_specifics_t asn_SPC_DeltaReferencePosition_specs_1;
extern asn_TYPE_member_t asn_MBR_DeltaReferencePosition_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _DeltaReferencePosition_H_ */
#include "asn_internal.h"
