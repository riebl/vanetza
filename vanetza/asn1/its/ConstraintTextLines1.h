/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IVI"
 * 	found in "build.asn1/iso/ISO19321.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ConstraintTextLines1_H_
#define	_ConstraintTextLines1_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Text;

/* ConstraintTextLines1 */
typedef struct ConstraintTextLines1 {
	A_SEQUENCE_OF(struct Text) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ConstraintTextLines1_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ConstraintTextLines1;
extern asn_SET_OF_specifics_t asn_SPC_ConstraintTextLines1_specs_1;
extern asn_TYPE_member_t asn_MBR_ConstraintTextLines1_1[1];
extern asn_per_constraints_t asn_PER_type_ConstraintTextLines1_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Text.h"

#endif	/* _ConstraintTextLines1_H_ */
#include "asn_internal.h"
