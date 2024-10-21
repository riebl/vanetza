/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/release2/TS103831v221-DENM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_ImpactReductionContainer_H_
#define	_Vanetza_ITS2_ImpactReductionContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "HeightLonCarr.h"
#include "PosLonCarr.h"
#include "PositionOfPillars.h"
#include "PosCentMass.h"
#include "WheelBaseVehicle.h"
#include "TurningRadius.h"
#include "PosFrontAx.h"
#include "PositionOfOccupants.h"
#include "VehicleMass.h"
#include "RequestResponseIndication.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_ITS2_ImpactReductionContainer */
typedef struct Vanetza_ITS2_ImpactReductionContainer {
	Vanetza_ITS2_HeightLonCarr_t	 heightLonCarrLeft;
	Vanetza_ITS2_HeightLonCarr_t	 heightLonCarrRight;
	Vanetza_ITS2_PosLonCarr_t	 posLonCarrLeft;
	Vanetza_ITS2_PosLonCarr_t	 posLonCarrRight;
	Vanetza_ITS2_PositionOfPillars_t	 positionOfPillars;
	Vanetza_ITS2_PosCentMass_t	 posCentMass;
	Vanetza_ITS2_WheelBaseVehicle_t	 wheelBaseVehicle;
	Vanetza_ITS2_TurningRadius_t	 turningRadius;
	Vanetza_ITS2_PosFrontAx_t	 posFrontAx;
	Vanetza_ITS2_PositionOfOccupants_t	 positionOfOccupants;
	Vanetza_ITS2_VehicleMass_t	 vehicleMass;
	Vanetza_ITS2_RequestResponseIndication_t	 requestResponseIndication;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_ImpactReductionContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_ImpactReductionContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_ImpactReductionContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_ImpactReductionContainer_1[12];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_ITS2_ImpactReductionContainer_H_ */
#include "asn_internal.h"