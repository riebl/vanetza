/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941BaseTypes"
 * 	found in "asn1/TS102941v131-BaseTypes.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#include "CertificateFormat.h"

int
CertificateFormat_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1L && value <= 255L)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

/*
 * This type is implemented using NativeInteger,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_OER_SUPPORT)
static asn_oer_constraints_t asn_OER_type_CertificateFormat_constr_1 CC_NOTUSED = {
	{ 1, 1 }	/* (1..255) */,
	-1};
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_CertificateFormat_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  1,  255 }	/* (1..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const ber_tlv_tag_t asn_DEF_CertificateFormat_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (2 << 2))
};
asn_TYPE_descriptor_t asn_DEF_CertificateFormat = {
	"CertificateFormat",
	"CertificateFormat",
	&asn_OP_NativeInteger,
	asn_DEF_CertificateFormat_tags_1,
	sizeof(asn_DEF_CertificateFormat_tags_1)
		/sizeof(asn_DEF_CertificateFormat_tags_1[0]), /* 1 */
	asn_DEF_CertificateFormat_tags_1,	/* Same as above */
	sizeof(asn_DEF_CertificateFormat_tags_1)
		/sizeof(asn_DEF_CertificateFormat_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		&asn_OER_type_CertificateFormat_constr_1,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_CertificateFormat_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		CertificateFormat_constraint
	},
	0, 0,	/* Defined elsewhere */
	0	/* No specifics */
};

