/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "AddGrpC"
 * 	found in "asn1/ISO-TS-19091-addgrp-C-2018-patched.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ConnectionTrajectory_addGrpC_H_
#define	_ConnectionTrajectory_addGrpC_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NodeSetXY.h"
#include "LaneConnectionID.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ConnectionTrajectory-addGrpC */
typedef struct ConnectionTrajectory_addGrpC {
	NodeSetXY_t	 nodes;
	LaneConnectionID_t	 connectionID;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ConnectionTrajectory_addGrpC_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ConnectionTrajectory_addGrpC;

#ifdef __cplusplus
}
#endif

#endif	/* _ConnectionTrajectory_addGrpC_H_ */
#include "asn_internal.h"
