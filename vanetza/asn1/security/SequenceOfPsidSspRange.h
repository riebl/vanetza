/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2BaseTypes"
 * 	found in "asn1/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_SequenceOfPsidSspRange_H_
#define	_SequenceOfPsidSspRange_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PsidSspRange;

/* SequenceOfPsidSspRange */
typedef struct SequenceOfPsidSspRange {
	A_SEQUENCE_OF(struct PsidSspRange) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfPsidSspRange_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfPsidSspRange;
extern asn_SET_OF_specifics_t asn_SPC_SequenceOfPsidSspRange_specs_1;
extern asn_TYPE_member_t asn_MBR_SequenceOfPsidSspRange_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _SequenceOfPsidSspRange_H_ */
#include "asn_internal.h"
