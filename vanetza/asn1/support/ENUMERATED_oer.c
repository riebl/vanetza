/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "ENUMERATED.h"
#include "NativeEnumerated.h"

asn_dec_rval_t
ENUMERATED_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_oer_constraints_t *constraints, void **sptr,
                      const void *ptr, size_t size) {
    asn_dec_rval_t rval;
    ENUMERATED_t *st = (ENUMERATED_t *)*sptr;
    long value;
    void *vptr = &value;

    if(!st) {
        st = (ENUMERATED_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    rval = NativeEnumerated_decode_oer(opt_codec_ctx, td, constraints,
                                       (void **)&vptr, ptr, size);
    if(rval.code == RC_OK) {
        if(asn_long2INTEGER(st, value)) {
            rval.code = RC_FAIL;
        }
    }
    return rval;
}

asn_enc_rval_t
ENUMERATED_encode_oer(const asn_TYPE_descriptor_t *td,
                      const asn_oer_constraints_t *constraints,
                      const void *sptr, asn_app_consume_bytes_f *cb,
                      void *app_key) {
    const ENUMERATED_t *st = sptr;
    long value;

    if(asn_INTEGER2long(st, &value)) {
        ASN__ENCODE_FAILED;
    }

    return NativeEnumerated_encode_oer(td, constraints, &value, cb, app_key);
}
