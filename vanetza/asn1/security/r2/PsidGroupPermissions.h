/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2"
 * 	found in "build.asn1/ieee/IEEE1609dot2.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_PsidGroupPermissions_H_
#define	_Vanetza_Security2_PsidGroupPermissions_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SubjectPermissions.h"
#include "NativeInteger.h"
#include "EndEntityType.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_Security2_PsidGroupPermissions */
typedef struct Vanetza_Security2_PsidGroupPermissions {
	Vanetza_Security2_SubjectPermissions_t	 subjectPermissions;
	long	*minChainLength;	/* DEFAULT 1 */
	long	 chainLengthRange;	/* DEFAULT 0 */
	Vanetza_Security2_EndEntityType_t	*eeType;	/* DEFAULT {app} */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_PsidGroupPermissions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_PsidGroupPermissions;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security2_PsidGroupPermissions_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_PsidGroupPermissions_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_PsidGroupPermissions_H_ */
#include "asn_internal.h"
