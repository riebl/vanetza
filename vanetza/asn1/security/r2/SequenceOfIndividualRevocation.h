/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2CrlBaseTypes"
 * 	found in "build.asn1/ieee/IEEE1609dot2crlBaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_SequenceOfIndividualRevocation_H_
#define	_Vanetza_Security2_SequenceOfIndividualRevocation_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_Security2_IndividualRevocation;

/* Vanetza_Security2_SequenceOfIndividualRevocation */
typedef struct Vanetza_Security2_SequenceOfIndividualRevocation {
	A_SEQUENCE_OF(struct Vanetza_Security2_IndividualRevocation) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_SequenceOfIndividualRevocation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_SequenceOfIndividualRevocation;
extern asn_SET_OF_specifics_t asn_SPC_Vanetza_Security2_SequenceOfIndividualRevocation_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_SequenceOfIndividualRevocation_1[1];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security2_SequenceOfIndividualRevocation_constr_1;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "IndividualRevocation.h"

#endif	/* _Vanetza_Security2_SequenceOfIndividualRevocation_H_ */
#include "asn_internal.h"
