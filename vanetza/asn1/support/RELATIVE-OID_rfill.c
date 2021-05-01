/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "RELATIVE-OID.h"

/*
 * Generate values from the list of interesting values, or just a random value.
 */
static asn_oid_arc_t
RELATIVE_OID__biased_random_arc() {
    static const uint16_t values[] = {0, 1, 127, 128, 129, 254, 255, 256};

    switch(asn_random_between(0, 2)) {
    case 0:
        return values[asn_random_between(
            0, sizeof(values) / sizeof(values[0]) - 1)];
    case 1:
        return asn_random_between(0, UINT_MAX);
    case 2:
    default:
        return UINT_MAX;
    }
}

asn_random_fill_result_t
RELATIVE_OID_random_fill(const asn_TYPE_descriptor_t *td, void **sptr,
                         const asn_encoding_constraints_t *constraints,
                         size_t max_length) {
    asn_random_fill_result_t result_ok = {ARFILL_OK, 1};
    asn_random_fill_result_t result_failed = {ARFILL_FAILED, 0};
    asn_random_fill_result_t result_skipped = {ARFILL_SKIPPED, 0};
    RELATIVE_OID_t *st;
    const int min_arcs = 1;  /* A minimum of 1 arc is required */
    asn_oid_arc_t arcs[3];
    size_t arcs_len =
        asn_random_between(min_arcs, sizeof(arcs) / sizeof(arcs[0]));
    size_t i;

    (void)constraints;

    if(max_length < arcs_len) return result_skipped;

    if(*sptr) {
        st = *sptr;
    } else {
        st = CALLOC(1, sizeof(*st));
    }

    for(i = 0; i < arcs_len; i++) {
        arcs[i] = RELATIVE_OID__biased_random_arc();
    }

    if(RELATIVE_OID_set_arcs(st, arcs, arcs_len)) {
        if(st != *sptr) {
            ASN_STRUCT_FREE(*td, st);
        }
        return result_failed;
    }

    *sptr = st;

    result_ok.length = st->size;
    return result_ok;
}
