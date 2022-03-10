/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "build.asn1/iso/ISO19091.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_TimeChangeDetails_H_
#define	_TimeChangeDetails_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TimeMark.h"
#include "TimeIntervalConfidence.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TimeChangeDetails */
typedef struct TimeChangeDetails {
	TimeMark_t	*startTime;	/* OPTIONAL */
	TimeMark_t	 minEndTime;
	TimeMark_t	*maxEndTime;	/* OPTIONAL */
	TimeMark_t	*likelyTime;	/* OPTIONAL */
	TimeIntervalConfidence_t	*confidence;	/* OPTIONAL */
	TimeMark_t	*nextTime;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TimeChangeDetails_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TimeChangeDetails;
extern asn_SEQUENCE_specifics_t asn_SPC_TimeChangeDetails_specs_1;
extern asn_TYPE_member_t asn_MBR_TimeChangeDetails_1[6];

#ifdef __cplusplus
}
#endif

#endif	/* _TimeChangeDetails_H_ */
#include "asn_internal.h"
