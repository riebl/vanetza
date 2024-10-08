/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IEEE1609dot2BaseTypes"
 * 	found in "asn1/IEEE1609dot2BaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#ifndef	_Vanetza_Security_SymmetricEncryptionKey_H_
#define	_Vanetza_Security_SymmetricEncryptionKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security_SymmetricEncryptionKey_PR {
	Vanetza_Security_SymmetricEncryptionKey_PR_NOTHING,	/* No components present */
	Vanetza_Security_SymmetricEncryptionKey_PR_aes128Ccm
	/* Extensions may appear below */
	
} Vanetza_Security_SymmetricEncryptionKey_PR;

/* Vanetza_Security_SymmetricEncryptionKey */
typedef struct Vanetza_Security_SymmetricEncryptionKey {
	Vanetza_Security_SymmetricEncryptionKey_PR present;
	union Vanetza_Security_SymmetricEncryptionKey_u {
		OCTET_STRING_t	 aes128Ccm;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security_SymmetricEncryptionKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_SymmetricEncryptionKey;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security_SymmetricEncryptionKey_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security_SymmetricEncryptionKey_1[1];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security_SymmetricEncryptionKey_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security_SymmetricEncryptionKey_H_ */
#include "asn_internal.h"
