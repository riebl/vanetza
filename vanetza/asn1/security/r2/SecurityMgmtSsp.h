/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2Dot1Protocol"
 * 	found in "build.asn1/ieee/IEEE1609dot2dot1Protocol.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_SecurityMgmtSsp_H_
#define	_Vanetza_Security2_SecurityMgmtSsp_H_


#include "asn_application.h"

/* Including external dependencies */
#include "ElectorSsp.h"
#include "RootCaSsp.h"
#include "PgSsp.h"
#include "IcaSsp.h"
#include "EcaSsp.h"
#include "AcaSsp.h"
#include "CrlSignerSsp.h"
#include "DcmSsp.h"
#include "LaSsp.h"
#include "LopSsp.h"
#include "MaSsp.h"
#include "RaSsp.h"
#include "EeSsp.h"
#include "DcSsp.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security2_SecurityMgmtSsp_PR {
	Vanetza_Security2_SecurityMgmtSsp_PR_NOTHING,	/* No components present */
	Vanetza_Security2_SecurityMgmtSsp_PR_elector,
	Vanetza_Security2_SecurityMgmtSsp_PR_root,
	Vanetza_Security2_SecurityMgmtSsp_PR_pg,
	Vanetza_Security2_SecurityMgmtSsp_PR_ica,
	Vanetza_Security2_SecurityMgmtSsp_PR_eca,
	Vanetza_Security2_SecurityMgmtSsp_PR_aca,
	Vanetza_Security2_SecurityMgmtSsp_PR_crl,
	Vanetza_Security2_SecurityMgmtSsp_PR_dcm,
	Vanetza_Security2_SecurityMgmtSsp_PR_la,
	Vanetza_Security2_SecurityMgmtSsp_PR_lop,
	Vanetza_Security2_SecurityMgmtSsp_PR_ma,
	Vanetza_Security2_SecurityMgmtSsp_PR_ra,
	Vanetza_Security2_SecurityMgmtSsp_PR_ee,
	/* Extensions may appear below */
	Vanetza_Security2_SecurityMgmtSsp_PR_dc
} Vanetza_Security2_SecurityMgmtSsp_PR;

/* Vanetza_Security2_SecurityMgmtSsp */
typedef struct Vanetza_Security2_SecurityMgmtSsp {
	Vanetza_Security2_SecurityMgmtSsp_PR present;
	union Vanetza_Security2_SecurityMgmtSsp_u {
		Vanetza_Security2_ElectorSsp_t	 elector;
		Vanetza_Security2_RootCaSsp_t	 root;
		Vanetza_Security2_PgSsp_t	 pg;
		Vanetza_Security2_IcaSsp_t	 ica;
		Vanetza_Security2_EcaSsp_t	 eca;
		Vanetza_Security2_AcaSsp_t	 aca;
		Vanetza_Security2_CrlSignerSsp_t	 crl;
		Vanetza_Security2_DcmSsp_t	 dcm;
		Vanetza_Security2_LaSsp_t	 la;
		Vanetza_Security2_LopSsp_t	 lop;
		Vanetza_Security2_MaSsp_t	 ma;
		Vanetza_Security2_RaSsp_t	 ra;
		Vanetza_Security2_EeSsp_t	 ee;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
		Vanetza_Security2_DcSsp_t	 dc;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_SecurityMgmtSsp_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_SecurityMgmtSsp;
extern asn_CHOICE_specifics_t asn_SPC_Vanetza_Security2_SecurityMgmtSsp_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_SecurityMgmtSsp_1[14];
extern asn_per_constraints_t asn_PER_type_Vanetza_Security2_SecurityMgmtSsp_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_SecurityMgmtSsp_H_ */
#include "asn_internal.h"
