/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2BaseTypes"
 * 	found in "asn1/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_PolygonalRegion_H_
#define	_PolygonalRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TwoDLocation;

/* PolygonalRegion */
typedef struct PolygonalRegion {
	A_SEQUENCE_OF(struct TwoDLocation) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PolygonalRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PolygonalRegion;
extern asn_SET_OF_specifics_t asn_SPC_PolygonalRegion_specs_1;
extern asn_TYPE_member_t asn_MBR_PolygonalRegion_1[1];
extern asn_per_constraints_t asn_PER_type_PolygonalRegion_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PolygonalRegion_H_ */
#include "asn_internal.h"
