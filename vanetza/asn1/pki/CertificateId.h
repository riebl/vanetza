/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2"
 * 	found in "asn1/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_CertificateId_H_
#define	_CertificateId_H_


#include "asn_application.h"

/* Including external dependencies */
#include "LinkageData.h"
#include "Hostname.h"
#include "OCTET_STRING.h"
#include "NULL.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CertificateId_PR {
	CertificateId_PR_NOTHING,	/* No components present */
	CertificateId_PR_linkageData,
	CertificateId_PR_name,
	CertificateId_PR_binaryId,
	CertificateId_PR_none
	/* Extensions may appear below */
	
} CertificateId_PR;

/* CertificateId */
typedef struct CertificateId {
	CertificateId_PR present;
	union CertificateId_u {
		LinkageData_t	 linkageData;
		Hostname_t	 name;
		OCTET_STRING_t	 binaryId;
		NULL_t	 none;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CertificateId_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CertificateId;
extern asn_CHOICE_specifics_t asn_SPC_CertificateId_specs_1;
extern asn_TYPE_member_t asn_MBR_CertificateId_1[4];
extern asn_per_constraints_t asn_PER_type_CertificateId_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _CertificateId_H_ */
#include "asn_internal.h"
