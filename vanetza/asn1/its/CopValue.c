/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EfcDsrcApplication"
 * 	found in "build.asn1/iso/ISO14906-0-6.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#include "CopValue.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_CopValue_constr_1 CC_NOTUSED = {
	{ 0, 0 },
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_CopValue_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  0,  8 }	/* (0..8) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_CopValue_value2enum_1[] = {
	{ 0,	7,	"noEntry" },
	{ 1,	9,	"co2class1" },
	{ 2,	9,	"co2class2" },
	{ 3,	9,	"co2class3" },
	{ 4,	9,	"co2class4" },
	{ 5,	9,	"co2class5" },
	{ 6,	9,	"co2class6" },
	{ 7,	9,	"co2class7" },
	{ 8,	14,	"reservedforUse" }
};
static const unsigned int asn_MAP_CopValue_enum2value_1[] = {
	1,	/* co2class1(1) */
	2,	/* co2class2(2) */
	3,	/* co2class3(3) */
	4,	/* co2class4(4) */
	5,	/* co2class5(5) */
	6,	/* co2class6(6) */
	7,	/* co2class7(7) */
	0,	/* noEntry(0) */
	8	/* reservedforUse(8) */
};
const asn_INTEGER_specifics_t asn_SPC_CopValue_specs_1 = {
	asn_MAP_CopValue_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_CopValue_enum2value_1,	/* N => "tag"; sorted by N */
	9,	/* Number of elements in the maps */
	0,	/* Enumeration is not extensible */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_CopValue_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_CopValue = {
	"CopValue",
	"CopValue",
	&asn_OP_NativeEnumerated,
	asn_DEF_CopValue_tags_1,
	sizeof(asn_DEF_CopValue_tags_1)
		/sizeof(asn_DEF_CopValue_tags_1[0]), /* 1 */
	asn_DEF_CopValue_tags_1,	/* Same as above */
	sizeof(asn_DEF_CopValue_tags_1)
		/sizeof(asn_DEF_CopValue_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_CopValue_constr_1,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_CopValue_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_CopValue_specs_1	/* Additional specs */
};

