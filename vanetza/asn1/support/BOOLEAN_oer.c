/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "BOOLEAN.h"

/*
 * Encode as Canonical OER.
 */
asn_enc_rval_t
BOOLEAN_encode_oer(const asn_TYPE_descriptor_t *td,
                   const asn_oer_constraints_t *constraints, const void *sptr,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = { 1, 0, 0 };
    const BOOLEAN_t *st = sptr;
    uint8_t bool_value = *st ? 0xff : 0; /* 0xff mandated by OER */

    (void)td;
    (void)constraints;  /* Constraints are unused in OER */

    if(cb(&bool_value, 1, app_key) < 0) {
        ASN__ENCODE_FAILED;
    } else {
        ASN__ENCODED_OK(er);
    }
}

asn_dec_rval_t
BOOLEAN_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td,
                   const asn_oer_constraints_t *constraints, void **sptr,
                   const void *ptr, size_t size) {
    asn_dec_rval_t ok = {RC_OK, 1};
    BOOLEAN_t *st;

    (void)opt_codec_ctx;
    (void)td;
    (void)constraints; /* Constraints are unused in OER */

    if(size < 1) {
        ASN__DECODE_STARVED;
    }

    if(!(st = *sptr)) {
        st = (BOOLEAN_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    *st = *(const uint8_t *)ptr;

    return ok;
}
