/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
/*
 * Read the NativeReal.h for the explanation wrt. differences between
 * REAL and NativeReal.
 * Basically, both are decoders and encoders of ASN.1 REAL type, but this
 * implementation deals with the standard (machine-specific) representation
 * of them instead of using the platform-independent buffer.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"
#include <math.h>

#if defined(__clang__)
/*
 * isnan() is defined using generic selections and won't compile in
 * strict C89 mode because of too fancy system's standard library.
 * However, prior to C11 the math had a perfectly working isnan()
 * in the math library.
 * Disable generic selection warning so we can test C89 mode with newer libc.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc11-extensions"
static int asn_isnan(double d) {
    return isnan(d);
}
#pragma clang diagnostic pop
#else
#define asn_isnan(v)    isnan(v)
#endif  /* generic selections */

/*
 * NativeReal basic type description.
 */
static const ber_tlv_tag_t asn_DEF_NativeReal_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (9 << 2))
};
asn_TYPE_operation_t asn_OP_NativeReal = {
    NativeReal_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    NativeReal_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    NativeReal_compare,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    NativeReal_decode_ber,
    NativeReal_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    NativeReal_decode_xer,
    NativeReal_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    NativeReal_decode_oer,
    NativeReal_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    NativeReal_decode_uper,
    NativeReal_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    NativeReal_decode_aper,
    NativeReal_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    NativeReal_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_NativeReal = {
    "REAL",  /* The ASN.1 type is still REAL */
    "REAL",
    &asn_OP_NativeReal,
    asn_DEF_NativeReal_tags,
    sizeof(asn_DEF_NativeReal_tags) / sizeof(asn_DEF_NativeReal_tags[0]),
    asn_DEF_NativeReal_tags,	/* Same as above */
    sizeof(asn_DEF_NativeReal_tags) / sizeof(asn_DEF_NativeReal_tags[0]),
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
        asn_generic_no_constraint
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

int
NativeReal_compare(const asn_TYPE_descriptor_t *td, const void *aptr,
                   const void *bptr) {

    if(aptr && bptr) {
        double a = NativeReal__get_double(td, aptr);
        double b = NativeReal__get_double(td, bptr);

        /* NaN sorted above everything else */
        if(asn_isnan(a)) {
            if(asn_isnan(b)) {
                return 0;
            } else {
                return -1;
            }
        } else if(asn_isnan(b)) {
            return 1;
        }
        /* Value comparison. */
        if(a < b) {
            return -1;
        } else if(a > b) {
            return 1;
        } else {
            return 0;
        }
    } else if(!aptr) {
        return -1;
    } else {
        return 1;
    }
}

void
NativeReal_free(const asn_TYPE_descriptor_t *td, void *ptr,
                enum asn_struct_free_method method) {
    if(!td || !ptr)
		return;

	ASN_DEBUG("Freeing %s as REAL (%d, %p, Native)",
		td->name, method, ptr);

    switch(method) {
    case ASFM_FREE_EVERYTHING:
        FREEMEM(ptr);
        break;
    case ASFM_FREE_UNDERLYING:
        break;
    case ASFM_FREE_UNDERLYING_AND_RESET: {
        const asn_NativeReal_specifics_t *specs;
        size_t float_size;
        specs = (const asn_NativeReal_specifics_t *)td->specifics;
        float_size = specs ? specs->float_size : sizeof(double);
        memset(ptr, 0, float_size);
    } break;
    }
}

/*
 * Local helper functions.
 */

size_t
NativeReal__float_size(const asn_TYPE_descriptor_t *td) {
    const asn_NativeReal_specifics_t *specs =
        (const asn_NativeReal_specifics_t *)td->specifics;
    return specs ? specs->float_size : sizeof(double);
}

double
NativeReal__get_double(const asn_TYPE_descriptor_t *td, const void *ptr) {
    size_t float_size = NativeReal__float_size(td);
    if(float_size == sizeof(float)) {
        return *(const float *)ptr;
    } else {
        return *(const double *)ptr;
    }
}

ssize_t  /* Returns -1 or float size. */
NativeReal__set(const asn_TYPE_descriptor_t *td, void **sptr, double d) {
    size_t float_size = NativeReal__float_size(td);
    void *native;

    if(!(native = *sptr)) {
        native = (*sptr = CALLOC(1, float_size));
        if(!native) {
            return -1;
        }
    }

    if(float_size == sizeof(float)) {
        if(asn_double2float(d, (float *)native)) {
            return -1;
        }
    } else {
        *(double *)native = d;
    }

    return float_size;
}

