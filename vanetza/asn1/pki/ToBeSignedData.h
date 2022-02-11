/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2"
 * 	found in "asn1/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_ToBeSignedData_H_
#define	_ToBeSignedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "HeaderInfo.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct SignedDataPayload;

/* ToBeSignedData */
typedef struct ToBeSignedData {
	struct SignedDataPayload	*payload;
	HeaderInfo_t	 headerInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ToBeSignedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ToBeSignedData;
extern asn_SEQUENCE_specifics_t asn_SPC_ToBeSignedData_specs_1;
extern asn_TYPE_member_t asn_MBR_ToBeSignedData_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _ToBeSignedData_H_ */
#include "asn_internal.h"
