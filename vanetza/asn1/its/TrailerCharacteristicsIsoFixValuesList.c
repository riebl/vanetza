/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "IVI"
 * 	found in "build.asn1/iso/ISO19321.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#include "TrailerCharacteristicsIsoFixValuesList.h"

static int
memb_VehicleCharacteristicsFixValues_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_memb_Member_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_PER_memb_Member_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  3,  3,  0,  6 }	/* (0..6,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_TrailerCharacteristicsIsoFixValuesList_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1	/* (SIZE(0..MAX)) */};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_TrailerCharacteristicsIsoFixValuesList_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  1,  4 }	/* (SIZE(1..4,...)) */,
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_member_t asn_MBR_TrailerCharacteristicsIsoFixValuesList_1[] = {
	{ ATF_POINTER, 0, 0,
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_VehicleCharacteristicsFixValues,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			&asn_OER_memb_Member_constr_2,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			&asn_PER_memb_Member_constr_2,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			memb_VehicleCharacteristicsFixValues_constraint_1
		},
		0, 0, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_TrailerCharacteristicsIsoFixValuesList_specs_1 = {
	sizeof(struct TrailerCharacteristicsIsoFixValuesList),
	offsetof(struct TrailerCharacteristicsIsoFixValuesList, _asn_ctx),
	2,	/* XER encoding is XMLValueList */
};
asn_TYPE_descriptor_t asn_DEF_TrailerCharacteristicsIsoFixValuesList = {
	"TrailerCharacteristicsIsoFixValuesList",
	"TrailerCharacteristicsIsoFixValuesList",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1,
	sizeof(asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1)
		/sizeof(asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1[0]), /* 1 */
	asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1,	/* Same as above */
	sizeof(asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1)
		/sizeof(asn_DEF_TrailerCharacteristicsIsoFixValuesList_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_TrailerCharacteristicsIsoFixValuesList_constr_1,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_TrailerCharacteristicsIsoFixValuesList_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_OF_constraint
	},
	asn_MBR_TrailerCharacteristicsIsoFixValuesList_1,
	1,	/* Single element */
	&asn_SPC_TrailerCharacteristicsIsoFixValuesList_specs_1	/* Additional specs */
};

