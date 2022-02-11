/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941TypesAuthorization"
 * 	found in "asn1/TS102941v131-TypesAuthorization.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_InnerAtRequest_H_
#define	_InnerAtRequest_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PublicKeys.h"
#include "OCTET_STRING.h"
#include "SharedAtRequest.h"
#include "EcSignature.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* InnerAtRequest */
typedef struct InnerAtRequest {
	PublicKeys_t	 publicKeys;
	OCTET_STRING_t	 hmacKey;
	SharedAtRequest_t	 sharedAtRequest;
	EcSignature_t	 ecSignature;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InnerAtRequest_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InnerAtRequest;
extern asn_SEQUENCE_specifics_t asn_SPC_InnerAtRequest_specs_1;
extern asn_TYPE_member_t asn_MBR_InnerAtRequest_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _InnerAtRequest_H_ */
#include "asn_internal.h"
