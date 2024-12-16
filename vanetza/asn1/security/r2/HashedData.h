/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2"
 * 	found in "build.asn1/ieee/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_HashedData_H_
#define	_Vanetza_Security2_HashedData_H_


#include "asn_application.h"

/* Including external dependencies */
#include "HashedId32.h"
#include "HashedId48.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security2_HashedData_PR {
	Vanetza_Security2_HashedData_PR_NOTHING,	/* No components present */
	Vanetza_Security2_HashedData_PR_sha256HashedData,
	/* Extensions may appear below */
	Vanetza_Security2_HashedData_PR_sha384HashedData,
	Vanetza_Security2_HashedData_PR_sm3HashedData
} Vanetza_Security2_HashedData_PR;

/* Vanetza_Security2_HashedData */
typedef struct Vanetza_Security2_HashedData {
	Vanetza_Security2_HashedData_PR present;
	union Vanetza_Security2_HashedData_u {
		Vanetza_Security2_HashedId32_t	 sha256HashedData;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
		Vanetza_Security2_HashedId48_t	 sha384HashedData;
		Vanetza_Security2_HashedId32_t	 sm3HashedData;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_HashedData_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_HashedData;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security2_HashedData_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_HashedData_1[3];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security2_HashedData_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_HashedData_H_ */
#include "asn_internal.h"
