/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "REGION"
 * 	found in "asn1/DSRC_REG_D.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#include "Reg-NodeOffsetPoint.h"

static const ber_tlv_tag_t asn_DEF_Reg_NodeOffsetPoint_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SEQUENCE_specifics_t asn_SPC_Reg_NodeOffsetPoint_specs_1 = {
	sizeof(struct Reg_NodeOffsetPoint),
	offsetof(struct Reg_NodeOffsetPoint, _asn_ctx),
	0,	/* No top level tags */
	0,	/* No tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	0,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Reg_NodeOffsetPoint = {
	"Reg-NodeOffsetPoint",
	"Reg-NodeOffsetPoint",
	&asn_OP_SEQUENCE,
	asn_DEF_Reg_NodeOffsetPoint_tags_1,
	sizeof(asn_DEF_Reg_NodeOffsetPoint_tags_1)
		/sizeof(asn_DEF_Reg_NodeOffsetPoint_tags_1[0]), /* 1 */
	asn_DEF_Reg_NodeOffsetPoint_tags_1,	/* Same as above */
	sizeof(asn_DEF_Reg_NodeOffsetPoint_tags_1)
		/sizeof(asn_DEF_Reg_NodeOffsetPoint_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	0, 0,	/* No members */
	&asn_SPC_Reg_NodeOffsetPoint_specs_1	/* Additional specs */
};

