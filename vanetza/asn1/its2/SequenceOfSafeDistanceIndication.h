/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_SequenceOfSafeDistanceIndication_H_
#define	_SequenceOfSafeDistanceIndication_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SafeDistanceIndication;

/* SequenceOfSafeDistanceIndication */
typedef struct SequenceOfSafeDistanceIndication {
	A_SEQUENCE_OF(struct SafeDistanceIndication) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfSafeDistanceIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfSafeDistanceIndication;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SafeDistanceIndication.h"

#endif	/* _SequenceOfSafeDistanceIndication_H_ */
#include "asn_internal.h"
