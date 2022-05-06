/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "GDD"
 * 	found in "build.asn1/iso/ISO14823.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_DDD_IO_H_
#define	_DDD_IO_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeInteger.h"
#include "UTF8String.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DestinationPlaces;
struct DestinationRoads;
struct DistanceOrDuration;

/* DDD-IO */
typedef struct DDD_IO {
	long	 arrowDirection;
	struct DestinationPlaces	*destPlace;	/* OPTIONAL */
	struct DestinationRoads	*destRoad;	/* OPTIONAL */
	long	*roadNumberIdentifier;	/* OPTIONAL */
	long	*streetName;	/* OPTIONAL */
	UTF8String_t	*streetNameText;	/* OPTIONAL */
	struct DistanceOrDuration	*distanceToDivergingPoint;	/* OPTIONAL */
	struct DistanceOrDuration	*distanceToDestinationPlace;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DDD_IO_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DDD_IO;
extern asn_SEQUENCE_specifics_t asn_SPC_DDD_IO_specs_1;
extern asn_TYPE_member_t asn_MBR_DDD_IO_1[8];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DestinationPlaces.h"
#include "DestinationRoads.h"
#include "DistanceOrDuration.h"

#endif	/* _DDD_IO_H_ */
#include "asn_internal.h"
