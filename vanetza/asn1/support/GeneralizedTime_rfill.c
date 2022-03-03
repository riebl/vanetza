/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "GeneralizedTime.h"

asn_random_fill_result_t
GeneralizedTime_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                              const asn_encoding_constraints_t *constraints,
                              size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    static const char *values[] = {
        "19700101000000",    "19700101000000-0000",   "19700101000000+0000",
        "19700101000000Z",   "19700101000000.3Z",     "19821106210623.3",
        "19821106210629.3Z", "19691106210827.3-0500", "19821106210629.456",
    };
    size_t rnd = asn_random_between(0, sizeof(values)/sizeof(values[0])-1);

    (void)constraints;

    if(max_length < sizeof("yyyymmddhhmmss") && !*sptr) {
        return result_skipped;
    }

    if(*sptr) {
        if(OCTET_STRING_fromBuf(*sptr, values[rnd], -1) != 0) {
            if(!sptr) return result_failed;
        }
    } else {
        *sptr = OCTET_STRING_new_fromBuf(td, values[rnd], -1);
        if(!sptr) return result_failed;
    }

    return result_ok;
}
