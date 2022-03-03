/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "REAL.h"

/*
 * Encode as Canonical OER
 */
asn_enc_rval_t
REAL_encode_oer(const asn_TYPE_descriptor_t *td,
                const asn_oer_constraints_t *constraints, const void *sptr,
                asn_app_consume_bytes_f *cb, void *app_key) {
    const REAL_t *st = sptr;
    asn_enc_rval_t er = {0,0,0};
    ssize_t len_len;

    if(!st || !st->buf || !td)
        ASN__ENCODE_FAILED;

    if(!constraints) constraints = td->encoding_constraints.oer_constraints;
    if(constraints && constraints->value.width != 0) {
        /* If we're constrained to a narrow float/double representation, we
         * shouldn't have ended up using REAL. Expecting NativeReal. */
        ASN__ENCODE_FAILED;
    }

    /* Encode a fake REAL */
    len_len = oer_serialize_length(st->size, cb, app_key);
    if(len_len < 0 || cb(st->buf, st->size, app_key) < 0) {
        ASN__ENCODE_FAILED;
    } else {
        er.encoded = len_len + st->size;
        ASN__ENCODED_OK(er);
    }
}

asn_dec_rval_t
REAL_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_oer_constraints_t *constraints, void **sptr,
                const void *ptr, size_t size) {
    asn_dec_rval_t ok = {RC_OK, 0};
    REAL_t *st;
    uint8_t *buf;
    ssize_t len_len;
    size_t real_body_len;

    (void)opt_codec_ctx;

    if(!constraints) constraints = td->encoding_constraints.oer_constraints;
    if(constraints && constraints->value.width != 0) {
        /* If we're constrained to a narrow float/double representation, we
         * shouldn't have ended up using REAL. Expecting NativeReal. */
        ASN__DECODE_FAILED;
    }

    len_len = oer_fetch_length(ptr, size, &real_body_len);
    if(len_len < 0) ASN__DECODE_FAILED;
    if(len_len == 0) ASN__DECODE_STARVED;

    ptr = (const char *)ptr + len_len;
    size -= len_len;

    if(real_body_len > size) ASN__DECODE_STARVED;

    buf = CALLOC(1, real_body_len + 1);
    if(!buf) ASN__DECODE_FAILED;

    if(!(st = *sptr)) {
        st = (*sptr = CALLOC(1, sizeof(REAL_t)));
        if(!st) {
            FREEMEM(buf);
            ASN__DECODE_FAILED;
        }
    } else {
        FREEMEM(st->buf);
    }

    memcpy(buf, ptr, real_body_len);
    buf[real_body_len] = '\0';

    st->buf = buf;
    st->size = real_body_len;

    ok.consumed = len_len + real_body_len;
    return ok;
}
