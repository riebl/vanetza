/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "REAL.h"
#include <math.h>
#include <float.h>

asn_random_fill_result_t
REAL_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                       const asn_encoding_constraints_t *constraints,
                       size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    static const double values[] = {
        0, -0.0, -1, 1, -M_E, M_E, -3.14, 3.14, -M_PI, M_PI, -255, 255,
        /* 2^51 */
        -2251799813685248.0, 2251799813685248.0,
        /* 2^52 */
        -4503599627370496.0, 4503599627370496.0,
        /* 2^100 */
        -1267650600228229401496703205376.0, 1267650600228229401496703205376.0,
        -FLT_MIN, FLT_MIN,
        -FLT_MAX, FLT_MAX,
        -DBL_MIN, DBL_MIN,
        -DBL_MAX, DBL_MAX,
#ifdef  FLT_TRUE_MIN
        -FLT_TRUE_MIN, FLT_TRUE_MIN,
#endif
#ifdef  DBL_TRUE_MIN
        -DBL_TRUE_MIN, DBL_TRUE_MIN,
#endif
        INFINITY, -INFINITY, NAN};
    REAL_t *st;
    double d;

    (void)constraints;

    if(max_length == 0) return result_skipped;

    d = values[asn_random_between(0, sizeof(values) / sizeof(values[0]) - 1)];

    if(*sptr) {
        st = *sptr;
    } else {
        st = (REAL_t*)(*sptr = CALLOC(1, sizeof(REAL_t)));
        if(!st) {
            return result_failed;
        }
    }

    if(asn_double2REAL(st, d)) {
        if(st == *sptr) {
            ASN_STRUCT_RESET(*td, st);
        } else {
            ASN_STRUCT_FREE(*td, st);
        }
        return result_failed;
    }

    result_ok.length = st->size;
    return result_ok;
}
