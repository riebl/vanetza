/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NULL.h"

asn_dec_rval_t
NULL_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_oer_constraints_t *constraints, void **sptr,
                const void *ptr, size_t size) {
    asn_dec_rval_t rv = {RC_OK, 0};
    (void)opt_codec_ctx;
    (void)td;
    (void)constraints;
    (void)ptr;
    (void)size;

    if(!*sptr) {
        *sptr = MALLOC(sizeof(NULL_t));
        if(*sptr) {
            *(NULL_t *)*sptr = 0;
        } else {
            ASN__DECODE_FAILED;
        }
    }

    return rv;
}

asn_enc_rval_t
NULL_encode_oer(const asn_TYPE_descriptor_t *td,
                const asn_oer_constraints_t *constraints, const void *sptr,
                asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};

    (void)td;
    (void)sptr;
    (void)constraints;
    (void)cb;
    (void)app_key;

    er.encoded = 0;  /* Encoding in 0 bytes. */

    ASN__ENCODED_OK(er);
}
