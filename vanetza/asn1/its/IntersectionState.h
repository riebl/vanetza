/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "DSRC"
 * 	found in "asn1/DSRC_REG_D.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_IntersectionState_H_
#define	_IntersectionState_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DescriptiveName.h"
#include "IntersectionReferenceID.h"
#include "MsgCount.h"
#include "IntersectionStatusObject.h"
#include "MinuteOfTheYear.h"
#include "DSecond2.h"
#include "MovementList.h"
#include "SignalControlState.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct EnabledLaneList;
struct ManeuverAssistList;
struct RegionalIntersectionState;

/* IntersectionState */
typedef struct IntersectionState {
	DescriptiveName_t	*name;	/* OPTIONAL */
	IntersectionReferenceID_t	 id;
	MsgCount_t	 revision;
	IntersectionStatusObject_t	 status;
	MinuteOfTheYear_t	*moy;	/* OPTIONAL */
	DSecond2_t	*timeStamp;	/* OPTIONAL */
	struct EnabledLaneList	*enabledLanes;	/* OPTIONAL */
	MovementList_t	 states;
	struct ManeuverAssistList	*maneuverAssistList;	/* OPTIONAL */
	SignalControlState_t	*priority;	/* OPTIONAL */
	SignalControlState_t	*preempt;	/* OPTIONAL */
	struct RegionalIntersectionState	*regional;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntersectionState_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntersectionState;
extern asn_SEQUENCE_specifics_t asn_SPC_IntersectionState_specs_1;
extern asn_TYPE_member_t asn_MBR_IntersectionState_1[12];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "EnabledLaneList.h"
#include "ManeuverAssistList.h"
#include "RegionalIntersectionState.h"

#endif	/* _IntersectionState_H_ */
#include "asn_internal.h"
