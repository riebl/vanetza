/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/DSRC_REG_D.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_NodeSet_H_
#define	_NodeSet_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Node;

/* NodeSet */
typedef struct NodeSet {
	A_SEQUENCE_OF(struct Node) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} NodeSet_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NodeSet;
extern asn_SET_OF_specifics_t asn_SPC_NodeSet_specs_1;
extern asn_TYPE_member_t asn_MBR_NodeSet_1[1];
extern asn_per_constraints_t asn_PER_type_NodeSet_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Node.h"

#endif	/* _NodeSet_H_ */
#include "asn_internal.h"
