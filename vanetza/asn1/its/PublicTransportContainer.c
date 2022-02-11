/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/EN302637-2v141-CAM.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#include "PublicTransportContainer.h"

#include "PtActivation.h"
asn_TYPE_member_t asn_MBR_PublicTransportContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct PublicTransportContainer, embarkationStatus),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EmbarkationStatus,
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
		"embarkationStatus"
		},
	{ ATF_POINTER, 1, offsetof(struct PublicTransportContainer, ptActivation),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PtActivation,
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
		"ptActivation"
		},
};
static const int asn_MAP_PublicTransportContainer_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_PublicTransportContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_PublicTransportContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* embarkationStatus */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* ptActivation */
};
asn_SEQUENCE_specifics_t asn_SPC_PublicTransportContainer_specs_1 = {
	sizeof(struct PublicTransportContainer),
	offsetof(struct PublicTransportContainer, _asn_ctx),
	asn_MAP_PublicTransportContainer_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_PublicTransportContainer_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_PublicTransportContainer = {
	"PublicTransportContainer",
	"PublicTransportContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_PublicTransportContainer_tags_1,
	sizeof(asn_DEF_PublicTransportContainer_tags_1)
		/sizeof(asn_DEF_PublicTransportContainer_tags_1[0]), /* 1 */
	asn_DEF_PublicTransportContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_PublicTransportContainer_tags_1)
		/sizeof(asn_DEF_PublicTransportContainer_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_PublicTransportContainer_1,
	2,	/* Elements count */
	&asn_SPC_PublicTransportContainer_specs_1	/* Additional specs */
};

