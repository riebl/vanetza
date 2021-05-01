/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "UTCTime.h"
#include "GeneralizedTime.h"
#include <errno.h>

#ifdef	__CYGWIN__
#include "/usr/include/time.h"
#else
#include <time.h>
#endif	/* __CYGWIN__ */

#ifndef	ASN___INTERNAL_TEST_MODE

/*
 * UTCTime basic type description.
 */
static const ber_tlv_tag_t asn_DEF_UTCTime_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (23 << 2)),  /* [UNIVERSAL 23] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (26 << 2)),  /* [UNIVERSAL 26] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_DEF_UTCTime_constraints = {
    { APC_CONSTRAINED, 7, 7, 0x20, 0x7e },   /* Value */
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },  /* Size */
    0, 0
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_operation_t asn_OP_UTCTime = {
    OCTET_STRING_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    UTCTime_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    UTCTime_compare,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    OCTET_STRING_decode_ber,  /* Implemented in terms of OCTET STRING */
    OCTET_STRING_encode_der,  /* Implemented in terms of OCTET STRING */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    OCTET_STRING_decode_xer_utf8,
    UTCTime_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    OCTET_STRING_decode_oer,
    OCTET_STRING_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    OCTET_STRING_decode_uper,
    OCTET_STRING_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    OCTET_STRING_decode_aper,
    OCTET_STRING_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    UTCTime_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_UTCTime = {
    "UTCTime",
    "UTCTime",
    &asn_OP_UTCTime,
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
      / sizeof(asn_DEF_UTCTime_tags[0]) - 2,
    asn_DEF_UTCTime_tags,
    sizeof(asn_DEF_UTCTime_tags)
      / sizeof(asn_DEF_UTCTime_tags[0]),
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        &asn_DEF_UTCTime_constraints,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
        UTCTime_constraint
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

#endif	/* ASN___INTERNAL_TEST_MODE */

/*
 * Check that the time looks like the time.
 */
int
UTCTime_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                   asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const UTCTime_t *st = (const UTCTime_t *)sptr;
	time_t tloc;

	errno = EPERM;			/* Just an unlikely error code */
	tloc = asn_UT2time(st, 0, 0);
	if(tloc == -1 && errno != EPERM) {
        ASN__CTFAIL(app_key, td, sptr, "%s: Invalid time format: %s (%s:%d)",
                    td->name, strerror(errno), __FILE__, __LINE__);
        return -1;
	}

	return 0;
}

time_t
asn_UT2time(const UTCTime_t *st, struct tm *_tm, int as_gmt) {
	char buf[24];	/* "AAMMJJhhmmss+hhmm" + cushion */
	GeneralizedTime_t gt;

	if(!st || !st->buf
	|| st->size < 11 || st->size >= ((int)sizeof(buf) - 2)) {
		errno = EINVAL;
		return -1;
	}

	gt.buf = (unsigned char *)buf;
	gt.size = st->size + 2;
	memcpy(gt.buf + 2, st->buf, st->size);
	if(st->buf[0] > 0x35) {
		/* 19xx */
		gt.buf[0] = 0x31;
		gt.buf[1] = 0x39;
	} else {
		/* 20xx */
		gt.buf[0] = 0x32;
		gt.buf[1] = 0x30;
	}

	return asn_GT2time(&gt, _tm, as_gmt);
}

UTCTime_t *
asn_time2UT(UTCTime_t *opt_ut, const struct tm *tm, int force_gmt) {
	GeneralizedTime_t *gt = (GeneralizedTime_t *)opt_ut;

	gt = asn_time2GT(gt, tm, force_gmt);
	if(gt == 0) return 0;

	assert(gt->size >= 2);
	gt->size -= 2;
	memmove(gt->buf, gt->buf + 2, gt->size + 1);

	return (UTCTime_t *)gt;
}

int
UTCTime_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                        const void *bptr) {
    const GeneralizedTime_t *a = aptr;
    const GeneralizedTime_t *b = bptr;

    (void)td;

    if(a && b) {
        time_t at, bt;
        int aerr, berr;

        errno = EPERM;
        at = asn_UT2time(a, 0, 0);
        aerr = errno;
        errno = EPERM;
        bt = asn_UT2time(b, 0, 0);
        berr = errno;

        if(at == -1 && aerr != EPERM) {
            if(bt == -1 && berr != EPERM) {
                return OCTET_STRING_compare(td, aptr, bptr);
            } else {
                return -1;
            }
        } else if(bt == -1 && berr != EPERM) {
            return 1;
        } else {
            /* Both values are valid. */
        }

        if(at < bt) {
            return -1;
        } else if(at > bt) {
            return 1;
        } else {
            return 0;
        }
    } else if(!a && !b) {
        return 0;
    } else if(!a) {
        return -1;
    } else {
        return 1;
    }
}

