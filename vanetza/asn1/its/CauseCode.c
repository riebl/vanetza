/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/TS102894-2v131-CDD.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#include "CauseCode.h"

asn_TYPE_member_t asn_MBR_CauseCode_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct CauseCode, causeCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_CauseCodeType,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"causeCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct CauseCode, subCauseCode),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SubCauseCodeType,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"subCauseCode"
		},
};
static const ber_tlv_tag_t asn_DEF_CauseCode_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_CauseCode_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* causeCode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* subCauseCode */
};
asn_SEQUENCE_specifics_t asn_SPC_CauseCode_specs_1 = {
	sizeof(struct CauseCode),
	offsetof(struct CauseCode, _asn_ctx),
	asn_MAP_CauseCode_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	2,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_CauseCode = {
	"CauseCode",
	"CauseCode",
	&asn_OP_SEQUENCE,
	asn_DEF_CauseCode_tags_1,
	sizeof(asn_DEF_CauseCode_tags_1)
		/sizeof(asn_DEF_CauseCode_tags_1[0]), /* 1 */
	asn_DEF_CauseCode_tags_1,	/* Same as above */
	sizeof(asn_DEF_CauseCode_tags_1)
		/sizeof(asn_DEF_CauseCode_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_CauseCode_1,
	2,	/* Elements count */
	&asn_SPC_CauseCode_specs_1	/* Additional specs */
};

