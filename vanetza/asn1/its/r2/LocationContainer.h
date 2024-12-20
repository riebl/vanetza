/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/release2/TS103831v221-DENM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_LocationContainer_H_
#define	_Vanetza_ITS2_LocationContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Traces.h"
#include "RoadType.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_ITS2_Speed;
struct Vanetza_ITS2_Wgs84Angle;
struct Vanetza_ITS2_GeneralizedLanePositions;
struct Vanetza_ITS2_OccupiedLanesWithConfidence;
struct Vanetza_ITS2_IvimReferences;
struct Vanetza_ITS2_MapReferences;
struct Vanetza_ITS2_TracesExtended;
struct Vanetza_ITS2_PathPredictedList;

/* Vanetza_ITS2_LocationContainer */
typedef struct Vanetza_ITS2_LocationContainer {
	struct Vanetza_ITS2_Speed	*eventSpeed;	/* OPTIONAL */
	struct Vanetza_ITS2_Wgs84Angle	*eventPositionHeading;	/* OPTIONAL */
	Vanetza_ITS2_Traces_t	 detectionZonesToEventPosition;
	Vanetza_ITS2_RoadType_t	*roadType;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	struct Vanetza_ITS2_LocationContainer__ext1 {
		struct Vanetza_ITS2_GeneralizedLanePositions	*lanePositions;	/* OPTIONAL */
		struct Vanetza_ITS2_OccupiedLanesWithConfidence	*occupiedLanes;	/* OPTIONAL */
		struct Vanetza_ITS2_IvimReferences	*linkedIvims;	/* OPTIONAL */
		struct Vanetza_ITS2_MapReferences	*linkedMapems;	/* OPTIONAL */
		struct Vanetza_ITS2_TracesExtended	*detectionZonesToSpecifiedEventPoint;	/* OPTIONAL */
		struct Vanetza_ITS2_PathPredictedList	*predictedPaths;	/* OPTIONAL */
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *ext1;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_LocationContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_LocationContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_LocationContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_LocationContainer_1[5];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Speed.h"
#include "Wgs84Angle.h"
#include "GeneralizedLanePositions.h"
#include "OccupiedLanesWithConfidence.h"
#include "IvimReferences.h"
#include "MapReferences.h"
#include "TracesExtended.h"
#include "PathPredictedList.h"

#endif	/* _Vanetza_ITS2_LocationContainer_H_ */
#include "asn_internal.h"
