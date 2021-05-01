/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include <math.h>
#include <float.h>

asn_random_fill_result_t
NativeReal_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                       const asn_encoding_constraints_t *constraints,
                       size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 0};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
#ifndef INFINITY
#define INFINITY (1.0/0.0)
#endif
#ifndef NAN
#define NAN (0.0/0.0)
#endif
    static const double double_values[] = {
        -M_E, M_E, -M_PI, M_PI, /* Better precision than with floats */
        -1E+308, 1E+308,
        /* 2^51 */
        -2251799813685248.0, 2251799813685248.0,
        /* 2^52 */
        -4503599627370496.0, 4503599627370496.0,
        /* 2^100 */
        -1267650600228229401496703205376.0, 1267650600228229401496703205376.0,
        -DBL_MIN, DBL_MIN,
        -DBL_MAX, DBL_MAX,
#ifdef  DBL_TRUE_MIN
        -DBL_TRUE_MIN, DBL_TRUE_MIN
#endif
    };
    static const float float_values[] = {
        0, -0.0, -1, 1, -M_E, M_E, -3.14, 3.14, -M_PI, M_PI, -255, 255,
        -FLT_MIN, FLT_MIN,
        -FLT_MAX, FLT_MAX,
#ifdef  FLT_TRUE_MIN
        -FLT_TRUE_MIN, FLT_TRUE_MIN,
#endif
        INFINITY, -INFINITY, NAN
    };
    ssize_t float_set_size = NativeReal__float_size(td);
    const size_t n_doubles = sizeof(double_values) / sizeof(double_values[0]);
    const size_t n_floats = sizeof(float_values) / sizeof(float_values[0]);
    double d;

    (void)constraints;

    if(max_length == 0) return result_skipped;

    if(float_set_size == sizeof(double) && asn_random_between(0, 1) == 0) {
        d = double_values[asn_random_between(0, n_doubles - 1)];
    } else {
        d = float_values[asn_random_between(0, n_floats - 1)];
    }

    if(NativeReal__set(td, sptr, d) < 0) {
        return result_failed;
    }

    result_ok.length = float_set_size;
    return result_ok;
}
