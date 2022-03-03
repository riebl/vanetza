/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "OBJECT_IDENTIFIER.h"

static enum xer_pbd_rval
OBJECT_IDENTIFIER__xer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                                   const void *chunk_buf, size_t chunk_size) {
    OBJECT_IDENTIFIER_t *st = (OBJECT_IDENTIFIER_t *)sptr;
    const char *chunk_end = (const char *)chunk_buf + chunk_size;
    const char *endptr;
    asn_oid_arc_t s_arcs[10];
    asn_oid_arc_t *arcs = s_arcs;
    ssize_t num_arcs;
    ssize_t ret;

    (void)td;

    num_arcs = OBJECT_IDENTIFIER_parse_arcs(
        (const char *)chunk_buf, chunk_size, arcs,
        sizeof(s_arcs) / sizeof(s_arcs[0]), &endptr);
    if(num_arcs < 0) {
        /* Expecting more than zero arcs */
        return XPBD_BROKEN_ENCODING;
    } else if(num_arcs == 0) {
        return XPBD_NOT_BODY_IGNORE;
    }
    (void)chunk_end;
    assert(endptr == chunk_end);

    if((size_t)num_arcs > sizeof(s_arcs)/sizeof(s_arcs[0])) {
        arcs = (asn_oid_arc_t *)MALLOC(num_arcs * sizeof(asn_oid_arc_t));
        if(!arcs) return XPBD_SYSTEM_FAILURE;
        ret = OBJECT_IDENTIFIER_parse_arcs((const char *)chunk_buf, chunk_size,
                                           arcs, num_arcs, &endptr);
        if(ret != num_arcs)
            return XPBD_SYSTEM_FAILURE;  /* assert?.. */
    }

    /*
     * Convert arcs into BER representation.
     */
    ret = OBJECT_IDENTIFIER_set_arcs(st, arcs, num_arcs);
    if(arcs != s_arcs) FREEMEM(arcs);

    return ret ? XPBD_SYSTEM_FAILURE : XPBD_BODY_CONSUMED;
}

asn_dec_rval_t
OBJECT_IDENTIFIER_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                             const asn_TYPE_descriptor_t *td, void **sptr,
                             const char *opt_mname, const void *buf_ptr,
                             size_t size) {
    return xer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(OBJECT_IDENTIFIER_t), opt_mname,
            buf_ptr, size, OBJECT_IDENTIFIER__xer_body_decode);
}

asn_enc_rval_t
OBJECT_IDENTIFIER_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                             int ilevel, enum xer_encoder_flags_e flags,
                             asn_app_consume_bytes_f *cb, void *app_key) {
    const OBJECT_IDENTIFIER_t *st = (const OBJECT_IDENTIFIER_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!st || !st->buf) {
        ASN__ENCODE_FAILED;
    }

    er.encoded = OBJECT_IDENTIFIER__dump_body(st, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
