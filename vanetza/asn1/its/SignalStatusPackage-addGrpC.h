/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "AddGrpC"
 * 	found in "build.asn1/iso/ISO19091.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_SignalStatusPackage_addGrpC_H_
#define	_SignalStatusPackage_addGrpC_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DeltaTime.h"
#include "RejectedReason.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SignalStatusPackage-addGrpC */
typedef struct SignalStatusPackage_addGrpC {
	DeltaTime_t	*synchToSchedule;	/* OPTIONAL */
	RejectedReason_t	*rejectedReason;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SignalStatusPackage_addGrpC_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SignalStatusPackage_addGrpC;

#ifdef __cplusplus
}
#endif

#endif	/* _SignalStatusPackage_addGrpC_H_ */
#include "asn_internal.h"
