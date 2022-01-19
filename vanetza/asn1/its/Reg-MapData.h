/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "REG-D"
 * 	found in "asn1/MAP_SPAT_REG_D.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_Reg_MapData_H_
#define	_Reg_MapData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SignalHeadLocationList;

/* Reg-MapData */
typedef struct Reg_MapData {
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct Reg_MapData__ext1 {
		struct SignalHeadLocationList	*signalHeadLocations;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_MapData_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Reg_MapData;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_MapData_specs_1;
extern asn_TYPE_member_t asn_MBR_Reg_MapData_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "SignalHeadLocationList.h"

#endif	/* _Reg_MapData_H_ */
#include "asn_internal.h"
