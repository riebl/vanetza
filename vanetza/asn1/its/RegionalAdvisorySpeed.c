/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/DSRC_REG_D.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#include "RegionalAdvisorySpeed.h"

/*
 * This type is implemented using Reg_AdvisorySpeed,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_RegionalAdvisorySpeed_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_RegionalAdvisorySpeed = {
	"RegionalAdvisorySpeed",
	"RegionalAdvisorySpeed",
	&asn_OP_SEQUENCE,
	asn_DEF_RegionalAdvisorySpeed_tags_1,
	sizeof(asn_DEF_RegionalAdvisorySpeed_tags_1)
		/sizeof(asn_DEF_RegionalAdvisorySpeed_tags_1[0]), /* 1 */
	asn_DEF_RegionalAdvisorySpeed_tags_1,	/* Same as above */
	sizeof(asn_DEF_RegionalAdvisorySpeed_tags_1)
		/sizeof(asn_DEF_RegionalAdvisorySpeed_tags_1[0]), /* 1 */
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
	&asn_SPC_Reg_AdvisorySpeed_specs_1	/* Additional specs */
};

