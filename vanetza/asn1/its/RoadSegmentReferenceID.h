/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/ISO-TS-19091-addgrp-C-2018-patched.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_RoadSegmentReferenceID_H_
#define	_RoadSegmentReferenceID_H_


#include "asn_application.h"

/* Including external dependencies */
#include "RoadRegulatorID.h"
#include "RoadSegmentID.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RoadSegmentReferenceID */
typedef struct RoadSegmentReferenceID {
	RoadRegulatorID_t	*region;	/* OPTIONAL */
	RoadSegmentID_t	 id;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RoadSegmentReferenceID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RoadSegmentReferenceID;
extern asn_SEQUENCE_specifics_t asn_SPC_RoadSegmentReferenceID_specs_1;
extern asn_TYPE_member_t asn_MBR_RoadSegmentReferenceID_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _RoadSegmentReferenceID_H_ */
#include "asn_internal.h"
