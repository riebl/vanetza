/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941MessagesCa"
 * 	found in "asn1/TS102941v131-MessagesCa.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_EtsiTs102941DataContent_H_
#define	_Vanetza_Security_EtsiTs102941DataContent_H_


#include "asn_application.h"

/* Including external dependencies */
#include "InnerEcRequestSignedForPop.h"
#include "InnerEcResponse.h"
#include "InnerAtRequest.h"
#include "InnerAtResponse.h"
#include "ToBeSignedCrl.h"
#include "ToBeSignedTlmCtl.h"
#include "ToBeSignedRcaCtl.h"
#include "AuthorizationValidationRequest.h"
#include "AuthorizationValidationResponse.h"
#include "CaCertificateRequest.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security_EtsiTs102941DataContent_PR {
	Vanetza_Security_EtsiTs102941DataContent_PR_NOTHING,	/* No components present */
	Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentRequest,
	Vanetza_Security_EtsiTs102941DataContent_PR_enrolmentResponse,
	Vanetza_Security_EtsiTs102941DataContent_PR_authorizationRequest,
	Vanetza_Security_EtsiTs102941DataContent_PR_authorizationResponse,
	Vanetza_Security_EtsiTs102941DataContent_PR_certificateRevocationList,
	Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListTlm,
	Vanetza_Security_EtsiTs102941DataContent_PR_certificateTrustListRca,
	Vanetza_Security_EtsiTs102941DataContent_PR_authorizationValidationRequest,
	Vanetza_Security_EtsiTs102941DataContent_PR_authorizationValidationResponse,
	Vanetza_Security_EtsiTs102941DataContent_PR_caCertificateRequest
	/* Extensions may appear below */
	
} Vanetza_Security_EtsiTs102941DataContent_PR;

/* Vanetza_Security_EtsiTs102941DataContent */
typedef struct Vanetza_Security_EtsiTs102941DataContent {
	Vanetza_Security_EtsiTs102941DataContent_PR present;
	union Vanetza_Security_EtsiTs102941DataContent_u {
		Vanetza_Security_InnerEcRequestSignedForPop_t	 enrolmentRequest;
		Vanetza_Security_InnerEcResponse_t	 enrolmentResponse;
		Vanetza_Security_InnerAtRequest_t	 authorizationRequest;
		Vanetza_Security_InnerAtResponse_t	 authorizationResponse;
		Vanetza_Security_ToBeSignedCrl_t	 certificateRevocationList;
		Vanetza_Security_ToBeSignedTlmCtl_t	 certificateTrustListTlm;
		Vanetza_Security_ToBeSignedRcaCtl_t	 certificateTrustListRca;
		Vanetza_Security_AuthorizationValidationRequest_t	 authorizationValidationRequest;
		Vanetza_Security_AuthorizationValidationResponse_t	 authorizationValidationResponse;
		Vanetza_Security_CaCertificateRequest_t	 caCertificateRequest;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_EtsiTs102941DataContent_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_EtsiTs102941DataContent;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security_EtsiTs102941DataContent_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_EtsiTs102941DataContent_1[10];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_EtsiTs102941DataContent_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security_EtsiTs102941DataContent_H_ */
#include "asn_internal.h"