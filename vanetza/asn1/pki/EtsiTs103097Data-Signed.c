/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs103097Module"
 * 	found in "asn1/TS103097v131.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#include "EtsiTs103097Data-Signed.h"

int
EtsiTs103097Data_Signed_55P0_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
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

/*
 * This type is implemented using EtsiTs103097Data,
 * so here we adjust the DEF accordingly.
 */
int
EtsiTs103097Data_Signed_55P1_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
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

/*
 * This type is implemented using EtsiTs103097Data,
 * so here we adjust the DEF accordingly.
 */
int
EtsiTs103097Data_Signed_55P2_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
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

/*
 * This type is implemented using EtsiTs103097Data,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_EtsiTs103097Data_Signed_55P0_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_EtsiTs103097Data_Signed_55P0_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_EtsiTs103097Data_Signed_55P1_constr_2 CC_NOTUSED = {
	{ 0, 0 },
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_EtsiTs103097Data_Signed_55P1_constr_2 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_EtsiTs103097Data_Signed_55P2_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_EtsiTs103097Data_Signed_55P2_constr_3 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const ber_tlv_tag_t asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_EtsiTs103097Data_Signed_55P0 = {
	"EtsiTs103097Data-Signed",
	"EtsiTs103097Data-Signed",
	&asn_OP_SEQUENCE,
	asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1,
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1[0]), /* 1 */
	asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1,	/* Same as above */
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P0_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_EtsiTs103097Data_Signed_55P0_constr_1,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_EtsiTs103097Data_Signed_55P0_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		EtsiTs103097Data_Signed_55P0_constraint
	},
	asn_MBR_Ieee1609Dot2Data_1,
	2,	/* Elements count */
	&asn_SPC_Ieee1609Dot2Data_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_EtsiTs103097Data_Signed_55P1 = {
	"EtsiTs103097Data-Signed",
	"EtsiTs103097Data-Signed",
	&asn_OP_SEQUENCE,
	asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2,
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2[0]), /* 1 */
	asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2,	/* Same as above */
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P1_tags_2[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_EtsiTs103097Data_Signed_55P1_constr_2,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_EtsiTs103097Data_Signed_55P1_constr_2,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		EtsiTs103097Data_Signed_55P1_constraint
	},
	asn_MBR_Ieee1609Dot2Data_1,
	2,	/* Elements count */
	&asn_SPC_Ieee1609Dot2Data_specs_1	/* Additional specs */
};

static const ber_tlv_tag_t asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_EtsiTs103097Data_Signed_55P2 = {
	"EtsiTs103097Data-Signed",
	"EtsiTs103097Data-Signed",
	&asn_OP_SEQUENCE,
	asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3,
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3[0]), /* 1 */
	asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3,	/* Same as above */
	sizeof(asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3)
		/sizeof(asn_DEF_EtsiTs103097Data_Signed_55P2_tags_3[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_EtsiTs103097Data_Signed_55P2_constr_3,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_EtsiTs103097Data_Signed_55P2_constr_3,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		EtsiTs103097Data_Signed_55P2_constraint
	},
	asn_MBR_Ieee1609Dot2Data_1,
	2,	/* Elements count */
	&asn_SPC_Ieee1609Dot2Data_specs_1	/* Additional specs */
};

