/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/release2/TS103900v211-CAM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_CamParameters_H_
#define	_Vanetza_ITS2_CamParameters_H_


#include "asn_application.h"

/* Including external dependencies */
#include "BasicContainer.h"
#include "HighFrequencyContainer.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_ITS2_LowFrequencyContainer;
struct Vanetza_ITS2_SpecialVehicleContainer;

/* Vanetza_ITS2_CamParameters */
typedef struct Vanetza_ITS2_CamParameters {
	Vanetza_ITS2_BasicContainer_t	 basicContainer;
	Vanetza_ITS2_HighFrequencyContainer_t	 highFrequencyContainer;
	struct Vanetza_ITS2_LowFrequencyContainer	*lowFrequencyContainer;	/* OPTIONAL */
	struct Vanetza_ITS2_SpecialVehicleContainer	*specialVehicleContainer;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_CamParameters_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_CamParameters;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_CamParameters_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_CamParameters_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "LowFrequencyContainer.h"
#include "SpecialVehicleContainer.h"

#endif	/* _Vanetza_ITS2_CamParameters_H_ */
#include "asn_internal.h"
