/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/ISO-TS-19091-addgrp-C-2018-patched.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_MovementList_H_
#define	_MovementList_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct MovementState;

/* MovementList */
typedef struct MovementList {
	A_SEQUENCE_OF(struct MovementState) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MovementList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MovementList;
extern asn_SET_OF_specifics_t asn_SPC_MovementList_specs_1;
extern asn_TYPE_member_t asn_MBR_MovementList_1[1];
extern asn_per_constraints_t asn_PER_type_MovementList_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "MovementState.h"

#endif	/* _MovementList_H_ */
#include "asn_internal.h"
