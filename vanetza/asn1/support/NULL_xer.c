/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "asn_codecs_prim.h"
#include "NULL.h"

asn_enc_rval_t
NULL_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
                void *app_key) {
    asn_enc_rval_t er = {0,0,0};

    (void)td;
    (void)sptr;
    (void)ilevel;
    (void)flags;
    (void)cb;
    (void)app_key;

    /* XMLNullValue is empty */
    er.encoded = 0;
    ASN__ENCODED_OK(er);
}


static enum xer_pbd_rval
NULL__xer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                      const void *chunk_buf, size_t chunk_size) {
    (void)td;
    (void)sptr;
    (void)chunk_buf;  /* Going to be empty according to the rules below. */

    /*
     * There must be no content in self-terminating <NULL/> tag.
     */
    if(chunk_size)
        return XPBD_BROKEN_ENCODING;
    else
        return XPBD_BODY_CONSUMED;
}

asn_dec_rval_t
NULL_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **sptr,
                const char *opt_mname, const void *buf_ptr, size_t size) {
    return xer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(NULL_t), opt_mname, buf_ptr, size,
        NULL__xer_body_decode);
}
