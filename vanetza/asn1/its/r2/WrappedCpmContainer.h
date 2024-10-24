/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/release2/TS103324v211/CPM-PDU-Descriptions.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_WrappedCpmContainer_H_
#define	_Vanetza_ITS2_WrappedCpmContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "CpmContainerId.h"
#include "ANY.h"
#include "asn_ioc.h"
#include "OriginatingVehicleContainer.h"
#include "OriginatingRsuContainer.h"
#include "SensorInformationContainer.h"
#include "PerceptionRegionContainer.h"
#include "PerceivedObjectContainer.h"
#include "OPEN_TYPE.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_ITS2_WrappedCpmContainer__containerData_PR {
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_NOTHING,	/* No components present */
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_OriginatingVehicleContainer,
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_OriginatingRsuContainer,
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_SensorInformationContainer,
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_PerceptionRegionContainer,
	Vanetza_ITS2_WrappedCpmContainer__containerData_PR_PerceivedObjectContainer
} Vanetza_ITS2_WrappedCpmContainer__containerData_PR;

/* Vanetza_ITS2_WrappedCpmContainer */
typedef struct Vanetza_ITS2_WrappedCpmContainer {
	Vanetza_ITS2_CpmContainerId_t	 containerId;
	struct Vanetza_ITS2_WrappedCpmContainer__containerData {
		Vanetza_ITS2_WrappedCpmContainer__containerData_PR present;
		union Vanetza_ITS2_WrappedCpmContainer__Vanetza_ITS2_containerData_u {
			Vanetza_ITS2_OriginatingVehicleContainer_t	 OriginatingVehicleContainer;
			Vanetza_ITS2_OriginatingRsuContainer_t	 OriginatingRsuContainer;
			Vanetza_ITS2_SensorInformationContainer_t	 SensorInformationContainer;
			Vanetza_ITS2_PerceptionRegionContainer_t	 PerceptionRegionContainer;
			Vanetza_ITS2_PerceivedObjectContainer_t	 PerceivedObjectContainer;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} containerData;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_WrappedCpmContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_WrappedCpmContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_WrappedCpmContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_WrappedCpmContainer_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_ITS2_WrappedCpmContainer_H_ */
#include "asn_internal.h"
