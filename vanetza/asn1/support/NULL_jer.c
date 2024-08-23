/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "asn_codecs_prim.h"
#include "NULL.h"

asn_enc_rval_t
NULL_encode_jer(const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints, const void *sptr,
                int ilevel, enum jer_encoder_flags_e flags,
                asn_app_consume_bytes_f *cb,
                void *app_key) {
    asn_enc_rval_t er = {0,0,0};

    (void)td;
    (void)sptr;
    (void)ilevel;
    (void)flags;

    ASN__CALLBACK("null", 4);
    ASN__ENCODED_OK(er);

cb_failed:
    ASN__ENCODE_FAILED;
}


static enum jer_pbd_rval
NULL__jer_body_decode(const asn_TYPE_descriptor_t *td,
                      void *sptr, const void *chunk_buf, size_t chunk_size) {

    (void)td;
    (void)sptr;

    const char *p = (const char *)chunk_buf;

    if(chunk_size && p[0] == 'n' /* 'null' */) {
        return JPBD_BODY_CONSUMED;
    } else {
        return JPBD_BROKEN_ENCODING;
    }
}

asn_dec_rval_t
NULL_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_jer_constraints_t *constraints,
                void **sptr, const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(NULL_t), buf_ptr, size,
        NULL__jer_body_decode);
}
