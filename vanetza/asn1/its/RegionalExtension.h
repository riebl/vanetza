/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/ISO-TS-19091-addgrp-C-2018-patched.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_RegionalExtension_H_
#define	_RegionalExtension_H_


#include "asn_application.h"

/* Including external dependencies */
#include "RegionId.h"
#include "ANY.h"
#include "asn_ioc.h"
#include "MapData-addGrpC.h"
#include "OPEN_TYPE.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"

struct ConnectionManeuverAssist_addGrpC_t;
struct ConnectionTrajectory_addGrpC_t;
struct IntersectionState_addGrpC_t;
struct LaneAttributes_addGrpC_t;
struct MovementEvent_addGrpC_t;
struct NodeAttributeSet_addGrpC_t;
struct Position3D_addGrpC_t;
struct RequestorDescription_addGrpC_t;
struct RestrictionUserType_addGrpC_t;
struct SignalStatusPackage_addGrpC_t;

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Reg_MapData__regExtValue_PR {
	Reg_MapData__regExtValue_PR_NOTHING,	/* No components present */
	Reg_MapData__regExtValue_PR_MapData_addGrpC
} Reg_MapData__regExtValue_PR;
typedef enum Reg_RTCMcorrections__regExtValue_PR {
	Reg_RTCMcorrections__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_RTCMcorrections__regExtValue_PR;
typedef enum Reg_SPAT__regExtValue_PR {
	Reg_SPAT__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SPAT__regExtValue_PR;
typedef enum Reg_SignalRequestMessage__regExtValue_PR {
	Reg_SignalRequestMessage__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalRequestMessage__regExtValue_PR;
typedef enum Reg_SignalStatusMessage__regExtValue_PR {
	Reg_SignalStatusMessage__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalStatusMessage__regExtValue_PR;
typedef enum Reg_AdvisorySpeed__regExtValue_PR {
	Reg_AdvisorySpeed__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_AdvisorySpeed__regExtValue_PR;
typedef enum Reg_ComputedLane__regExtValue_PR {
	Reg_ComputedLane__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_ComputedLane__regExtValue_PR;
typedef enum Reg_ConnectionManeuverAssist__regExtValue_PR {
	Reg_ConnectionManeuverAssist__regExtValue_PR_NOTHING,	/* No components present */
	Reg_ConnectionManeuverAssist__regExtValue_PR_ConnectionManeuverAssist_addGrpC
} Reg_ConnectionManeuverAssist__regExtValue_PR;
typedef enum Reg_GenericLane__regExtValue_PR {
	Reg_GenericLane__regExtValue_PR_NOTHING,	/* No components present */
	Reg_GenericLane__regExtValue_PR_ConnectionTrajectory_addGrpC
} Reg_GenericLane__regExtValue_PR;
typedef enum Reg_IntersectionGeometry__regExtValue_PR {
	Reg_IntersectionGeometry__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_IntersectionGeometry__regExtValue_PR;
typedef enum Reg_IntersectionState__regExtValue_PR {
	Reg_IntersectionState__regExtValue_PR_NOTHING,	/* No components present */
	Reg_IntersectionState__regExtValue_PR_IntersectionState_addGrpC
} Reg_IntersectionState__regExtValue_PR;
typedef enum Reg_LaneAttributes__regExtValue_PR {
	Reg_LaneAttributes__regExtValue_PR_NOTHING,	/* No components present */
	Reg_LaneAttributes__regExtValue_PR_LaneAttributes_addGrpC
} Reg_LaneAttributes__regExtValue_PR;
typedef enum Reg_LaneDataAttribute__regExtValue_PR {
	Reg_LaneDataAttribute__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_LaneDataAttribute__regExtValue_PR;
typedef enum Reg_MovementEvent__regExtValue_PR {
	Reg_MovementEvent__regExtValue_PR_NOTHING,	/* No components present */
	Reg_MovementEvent__regExtValue_PR_MovementEvent_addGrpC
} Reg_MovementEvent__regExtValue_PR;
typedef enum Reg_MovementState__regExtValue_PR {
	Reg_MovementState__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_MovementState__regExtValue_PR;
typedef enum Reg_NodeAttributeSetXY__regExtValue_PR {
	Reg_NodeAttributeSetXY__regExtValue_PR_NOTHING,	/* No components present */
	Reg_NodeAttributeSetXY__regExtValue_PR_NodeAttributeSet_addGrpC
} Reg_NodeAttributeSetXY__regExtValue_PR;
typedef enum Reg_NodeOffsetPointXY__regExtValue_PR {
	Reg_NodeOffsetPointXY__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_NodeOffsetPointXY__regExtValue_PR;
typedef enum Reg_Position3D__regExtValue_PR {
	Reg_Position3D__regExtValue_PR_NOTHING,	/* No components present */
	Reg_Position3D__regExtValue_PR_Position3D_addGrpC
} Reg_Position3D__regExtValue_PR;
typedef enum Reg_RequestorDescription__regExtValue_PR {
	Reg_RequestorDescription__regExtValue_PR_NOTHING,	/* No components present */
	Reg_RequestorDescription__regExtValue_PR_RequestorDescription_addGrpC
} Reg_RequestorDescription__regExtValue_PR;
typedef enum Reg_RequestorType__regExtValue_PR {
	Reg_RequestorType__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_RequestorType__regExtValue_PR;
typedef enum Reg_RestrictionUserType__regExtValue_PR {
	Reg_RestrictionUserType__regExtValue_PR_NOTHING,	/* No components present */
	Reg_RestrictionUserType__regExtValue_PR_RestrictionUserType_addGrpC
} Reg_RestrictionUserType__regExtValue_PR;
typedef enum Reg_RoadSegment__regExtValue_PR {
	Reg_RoadSegment__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_RoadSegment__regExtValue_PR;
typedef enum Reg_SignalControlZone__regExtValue_PR {
	Reg_SignalControlZone__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalControlZone__regExtValue_PR;
typedef enum Reg_SignalRequest__regExtValue_PR {
	Reg_SignalRequest__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalRequest__regExtValue_PR;
typedef enum Reg_SignalRequestPackage__regExtValue_PR {
	Reg_SignalRequestPackage__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalRequestPackage__regExtValue_PR;
typedef enum Reg_SignalStatus__regExtValue_PR {
	Reg_SignalStatus__regExtValue_PR_NOTHING	/* No components present */
	
} Reg_SignalStatus__regExtValue_PR;
typedef enum Reg_SignalStatusPackage__regExtValue_PR {
	Reg_SignalStatusPackage__regExtValue_PR_NOTHING,	/* No components present */
	Reg_SignalStatusPackage__regExtValue_PR_SignalStatusPackage_addGrpC
} Reg_SignalStatusPackage__regExtValue_PR;

/* RegionalExtension */
typedef struct Reg_MapData {
	RegionId_t	 regionId;
	struct Reg_MapData__regExtValue {
		Reg_MapData__regExtValue_PR present;
		union Reg_MapData__regExtValue_u {
			MapData_addGrpC_t	 MapData_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_MapData_t;
typedef struct Reg_RTCMcorrections {
	RegionId_t	 regionId;
	struct Reg_RTCMcorrections__regExtValue {
		Reg_RTCMcorrections__regExtValue_PR present;
		union Reg_RTCMcorrections__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_RTCMcorrections_t;
typedef struct Reg_SPAT {
	RegionId_t	 regionId;
	struct Reg_SPAT__regExtValue {
		Reg_SPAT__regExtValue_PR present;
		union Reg_SPAT__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SPAT_t;
typedef struct Reg_SignalRequestMessage {
	RegionId_t	 regionId;
	struct Reg_SignalRequestMessage__regExtValue {
		Reg_SignalRequestMessage__regExtValue_PR present;
		union Reg_SignalRequestMessage__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalRequestMessage_t;
typedef struct Reg_SignalStatusMessage {
	RegionId_t	 regionId;
	struct Reg_SignalStatusMessage__regExtValue {
		Reg_SignalStatusMessage__regExtValue_PR present;
		union Reg_SignalStatusMessage__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalStatusMessage_t;
typedef struct Reg_AdvisorySpeed {
	RegionId_t	 regionId;
	struct Reg_AdvisorySpeed__regExtValue {
		Reg_AdvisorySpeed__regExtValue_PR present;
		union Reg_AdvisorySpeed__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_AdvisorySpeed_t;
typedef struct Reg_ComputedLane {
	RegionId_t	 regionId;
	struct Reg_ComputedLane__regExtValue {
		Reg_ComputedLane__regExtValue_PR present;
		union Reg_ComputedLane__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_ComputedLane_t;
typedef struct Reg_ConnectionManeuverAssist {
	RegionId_t	 regionId;
	struct Reg_ConnectionManeuverAssist__regExtValue {
		Reg_ConnectionManeuverAssist__regExtValue_PR present;
		union Reg_ConnectionManeuverAssist__regExtValue_u {
			struct ConnectionManeuverAssist_addGrpC_t*	 ConnectionManeuverAssist_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_ConnectionManeuverAssist_t;
typedef struct Reg_GenericLane {
	RegionId_t	 regionId;
	struct Reg_GenericLane__regExtValue {
		Reg_GenericLane__regExtValue_PR present;
		union Reg_GenericLane__regExtValue_u {
            struct ConnectionTrajectory_addGrpC_t*	 ConnectionTrajectory_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_GenericLane_t;
typedef struct Reg_IntersectionGeometry {
	RegionId_t	 regionId;
	struct Reg_IntersectionGeometry__regExtValue {
		Reg_IntersectionGeometry__regExtValue_PR present;
		union Reg_IntersectionGeometry__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_IntersectionGeometry_t;
typedef struct Reg_IntersectionState {
	RegionId_t	 regionId;
	struct Reg_IntersectionState__regExtValue {
		Reg_IntersectionState__regExtValue_PR present;
		union Reg_IntersectionState__regExtValue_u {
            struct IntersectionState_addGrpC_t*	 IntersectionState_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_IntersectionState_t;
typedef struct Reg_LaneAttributes {
	RegionId_t	 regionId;
	struct Reg_LaneAttributes__regExtValue {
		Reg_LaneAttributes__regExtValue_PR present;
		union Reg_LaneAttributes__regExtValue_u {
            struct LaneAttributes_addGrpC_t*	 LaneAttributes_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_LaneAttributes_t;
typedef struct Reg_LaneDataAttribute {
	RegionId_t	 regionId;
	struct Reg_LaneDataAttribute__regExtValue {
		Reg_LaneDataAttribute__regExtValue_PR present;
		union Reg_LaneDataAttribute__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_LaneDataAttribute_t;
typedef struct Reg_MovementEvent {
	RegionId_t	 regionId;
	struct Reg_MovementEvent__regExtValue {
		Reg_MovementEvent__regExtValue_PR present;
		union Reg_MovementEvent__regExtValue_u {
            struct MovementEvent_addGrpC_t*	 MovementEvent_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_MovementEvent_t;
typedef struct Reg_MovementState {
	RegionId_t	 regionId;
	struct Reg_MovementState__regExtValue {
		Reg_MovementState__regExtValue_PR present;
		union Reg_MovementState__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_MovementState_t;
typedef struct Reg_NodeAttributeSetXY {
	RegionId_t	 regionId;
	struct Reg_NodeAttributeSetXY__regExtValue {
		Reg_NodeAttributeSetXY__regExtValue_PR present;
		union Reg_NodeAttributeSetXY__regExtValue_u {
			struct NodeAttributeSet_addGrpC_t*	 NodeAttributeSet_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_NodeAttributeSetXY_t;
typedef struct Reg_NodeOffsetPointXY {
	RegionId_t	 regionId;
	struct Reg_NodeOffsetPointXY__regExtValue {
		Reg_NodeOffsetPointXY__regExtValue_PR present;
		union Reg_NodeOffsetPointXY__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_NodeOffsetPointXY_t;
typedef struct Reg_Position3D {
	RegionId_t	 regionId;
	struct Reg_Position3D__regExtValue {
		Reg_Position3D__regExtValue_PR present;
		union Reg_Position3D__regExtValue_u {
            struct Position3D_addGrpC_t*	 Position3D_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_Position3D_t;
typedef struct Reg_RequestorDescription {
	RegionId_t	 regionId;
	struct Reg_RequestorDescription__regExtValue {
		Reg_RequestorDescription__regExtValue_PR present;
		union Reg_RequestorDescription__regExtValue_u {
            struct RequestorDescription_addGrpC_t*	 RequestorDescription_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_RequestorDescription_t;
typedef struct Reg_RequestorType {
	RegionId_t	 regionId;
	struct Reg_RequestorType__regExtValue {
		Reg_RequestorType__regExtValue_PR present;
		union Reg_RequestorType__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_RequestorType_t;
typedef struct Reg_RestrictionUserType {
	RegionId_t	 regionId;
	struct Reg_RestrictionUserType__regExtValue {
		Reg_RestrictionUserType__regExtValue_PR present;
		union Reg_RestrictionUserType__regExtValue_u {
            struct RestrictionUserType_addGrpC_t*	 RestrictionUserType_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_RestrictionUserType_t;
typedef struct Reg_RoadSegment {
	RegionId_t	 regionId;
	struct Reg_RoadSegment__regExtValue {
		Reg_RoadSegment__regExtValue_PR present;
		union Reg_RoadSegment__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_RoadSegment_t;
typedef struct Reg_SignalControlZone {
	RegionId_t	 regionId;
	struct Reg_SignalControlZone__regExtValue {
		Reg_SignalControlZone__regExtValue_PR present;
		union Reg_SignalControlZone__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalControlZone_t;
typedef struct Reg_SignalRequest {
	RegionId_t	 regionId;
	struct Reg_SignalRequest__regExtValue {
		Reg_SignalRequest__regExtValue_PR present;
		union Reg_SignalRequest__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalRequest_t;
typedef struct Reg_SignalRequestPackage {
	RegionId_t	 regionId;
	struct Reg_SignalRequestPackage__regExtValue {
		Reg_SignalRequestPackage__regExtValue_PR present;
		union Reg_SignalRequestPackage__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalRequestPackage_t;
typedef struct Reg_SignalStatus {
	RegionId_t	 regionId;
	struct Reg_SignalStatus__regExtValue {
		Reg_SignalStatus__regExtValue_PR present;
		union Reg_SignalStatus__regExtValue_u {
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalStatus_t;
typedef struct Reg_SignalStatusPackage {
	RegionId_t	 regionId;
	struct Reg_SignalStatusPackage__regExtValue {
		Reg_SignalStatusPackage__regExtValue_PR present;
		union Reg_SignalStatusPackage__regExtValue_u {
			struct SignalStatusPackage_addGrpC_t*	 SignalStatusPackage_addGrpC;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} regExtValue;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Reg_SignalStatusPackage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Reg_MapData;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_MapData_specs_1;
extern asn_TYPE_member_t asn_MBR_Reg_MapData_1[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_RTCMcorrections;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_RTCMcorrections_specs_4;
extern asn_TYPE_member_t asn_MBR_Reg_RTCMcorrections_4[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SPAT;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SPAT_specs_7;
extern asn_TYPE_member_t asn_MBR_Reg_SPAT_7[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalRequestMessage;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalRequestMessage_specs_10;
extern asn_TYPE_member_t asn_MBR_Reg_SignalRequestMessage_10[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalStatusMessage;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalStatusMessage_specs_13;
extern asn_TYPE_member_t asn_MBR_Reg_SignalStatusMessage_13[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_AdvisorySpeed;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_AdvisorySpeed_specs_16;
extern asn_TYPE_member_t asn_MBR_Reg_AdvisorySpeed_16[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_ComputedLane;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_ComputedLane_specs_19;
extern asn_TYPE_member_t asn_MBR_Reg_ComputedLane_19[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_ConnectionManeuverAssist;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_ConnectionManeuverAssist_specs_22;
extern asn_TYPE_member_t asn_MBR_Reg_ConnectionManeuverAssist_22[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_GenericLane;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_GenericLane_specs_25;
extern asn_TYPE_member_t asn_MBR_Reg_GenericLane_25[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_IntersectionGeometry;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_IntersectionGeometry_specs_28;
extern asn_TYPE_member_t asn_MBR_Reg_IntersectionGeometry_28[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_IntersectionState;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_IntersectionState_specs_31;
extern asn_TYPE_member_t asn_MBR_Reg_IntersectionState_31[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_LaneAttributes;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_LaneAttributes_specs_34;
extern asn_TYPE_member_t asn_MBR_Reg_LaneAttributes_34[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_LaneDataAttribute;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_LaneDataAttribute_specs_37;
extern asn_TYPE_member_t asn_MBR_Reg_LaneDataAttribute_37[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_MovementEvent;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_MovementEvent_specs_40;
extern asn_TYPE_member_t asn_MBR_Reg_MovementEvent_40[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_MovementState;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_MovementState_specs_43;
extern asn_TYPE_member_t asn_MBR_Reg_MovementState_43[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_NodeAttributeSetXY;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_NodeAttributeSetXY_specs_46;
extern asn_TYPE_member_t asn_MBR_Reg_NodeAttributeSetXY_46[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_NodeOffsetPointXY;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_NodeOffsetPointXY_specs_49;
extern asn_TYPE_member_t asn_MBR_Reg_NodeOffsetPointXY_49[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_Position3D;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_Position3D_specs_52;
extern asn_TYPE_member_t asn_MBR_Reg_Position3D_52[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_RequestorDescription;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_RequestorDescription_specs_55;
extern asn_TYPE_member_t asn_MBR_Reg_RequestorDescription_55[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_RequestorType;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_RequestorType_specs_58;
extern asn_TYPE_member_t asn_MBR_Reg_RequestorType_58[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_RestrictionUserType;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_RestrictionUserType_specs_61;
extern asn_TYPE_member_t asn_MBR_Reg_RestrictionUserType_61[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_RoadSegment;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_RoadSegment_specs_64;
extern asn_TYPE_member_t asn_MBR_Reg_RoadSegment_64[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalControlZone;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalControlZone_specs_67;
extern asn_TYPE_member_t asn_MBR_Reg_SignalControlZone_67[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalRequest;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalRequest_specs_70;
extern asn_TYPE_member_t asn_MBR_Reg_SignalRequest_70[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalRequestPackage;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalRequestPackage_specs_73;
extern asn_TYPE_member_t asn_MBR_Reg_SignalRequestPackage_73[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalStatus;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalStatus_specs_76;
extern asn_TYPE_member_t asn_MBR_Reg_SignalStatus_76[2];
extern asn_TYPE_descriptor_t asn_DEF_Reg_SignalStatusPackage;
extern asn_SEQUENCE_specifics_t asn_SPC_Reg_SignalStatusPackage_specs_79;
extern asn_TYPE_member_t asn_MBR_Reg_SignalStatusPackage_79[2];

#ifdef __cplusplus
}
#endif

#include "ConnectionManeuverAssist-addGrpC.h"
#include "ConnectionTrajectory-addGrpC.h"
#include "IntersectionState-addGrpC.h"
#include "LaneAttributes-addGrpC.h"
#include "MovementEvent-addGrpC.h"
#include "NodeAttributeSet-addGrpC.h"
#include "Position3D-addGrpC.h"
#include "RequestorDescription-addGrpC.h"
#include "RestrictionUserType-addGrpC.h"
#include "SignalStatusPackage-addGrpC.h"

#endif	/* _RegionalExtension_H_ */
#include "asn_internal.h"
