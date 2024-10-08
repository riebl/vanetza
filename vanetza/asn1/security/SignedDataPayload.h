/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2"
 * 	found in "asn1/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_SignedDataPayload_H_
#define	_Vanetza_Security_SignedDataPayload_H_


#include "asn_application.h"

/* Including external dependencies */
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_Security_Ieee1609Dot2Data;
struct Vanetza_Security_HashedData;

/* Vanetza_Security_SignedDataPayload */
typedef struct Vanetza_Security_SignedDataPayload {
	struct Vanetza_Security_Ieee1609Dot2Data	*data;	/* OPTIONAL */
	struct Vanetza_Security_HashedData	*extDataHash;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_SignedDataPayload_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_SignedDataPayload;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security_SignedDataPayload_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_SignedDataPayload_1[2];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_SignedDataPayload_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Ieee1609Dot2Data.h"
#include "HashedData.h"

#endif	/* _Vanetza_Security_SignedDataPayload_H_ */
#include "asn_internal.h"
