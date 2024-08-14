/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "asn_codecs_prim.h"
#include "BOOLEAN.h"
#include <errno.h>

/*
 * Decode the chunk of JSON text encoding INTEGER.
 */
static enum jer_pbd_rval
BOOLEAN__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    BOOLEAN_t *st = (BOOLEAN_t *)sptr;
    const char *p = (const char *)chunk_buf;

    (void)td;
    (void)chunk_size;

    if(p[0] == 't' /* 'true' */) {
        *st = 1;
        return JPBD_BODY_CONSUMED;
    } else if (p[0] == 'f' /* 'false' */) {
        *st = 0;
        return JPBD_BODY_CONSUMED;
    } else {
        return JPBD_BROKEN_ENCODING;
    }
}


asn_dec_rval_t
BOOLEAN_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **sptr,
                   const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td,
                                sptr, sizeof(BOOLEAN_t), buf_ptr, size,
                                BOOLEAN__jer_body_decode);
}


asn_enc_rval_t
BOOLEAN_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};

    (void)ilevel;
    (void)flags;

    if(!st) ASN__ENCODE_FAILED;

    if(*st) {
        ASN__CALLBACK("true", 4);
    } else {
        ASN__CALLBACK("false", 5);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
