/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "RELATIVE-OID.h"

#define CQUOTE 0x22

static enum jer_pbd_rval
RELATIVE_OID__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                              const void *chunk_buf, size_t chunk_size) {
    RELATIVE_OID_t *st = (RELATIVE_OID_t *)sptr;
    const char *chunk_end = (const char *)chunk_buf + chunk_size;
    const char* p = (const char*)chunk_buf;
    const char *endptr;
    asn_oid_arc_t s_arcs[6];
    asn_oid_arc_t *arcs = s_arcs;
    ssize_t num_arcs;
    int ret;

    (void)td;

    /* Strip quotes */
    for (; p < chunk_end; ++p) {
        if (*p == CQUOTE) {
            ++p;
            break;
        }
    }
    --chunk_end;
    for (; chunk_end >= p; --chunk_end) {
        if (*chunk_end == CQUOTE) 
            break;
    }
    if (chunk_end - p < 0) 
        return JPBD_BROKEN_ENCODING;
    chunk_size = chunk_end - p;
    chunk_buf = p;

    num_arcs = OBJECT_IDENTIFIER_parse_arcs(
        (const char *)chunk_buf, chunk_size, arcs,
        sizeof(s_arcs) / sizeof(s_arcs[0]), &endptr);
    if(num_arcs < 0) {
        /* Expecting at least one arc arcs */
        return JPBD_BROKEN_ENCODING;
    } else if(num_arcs == 0) {
        return JPBD_NOT_BODY_IGNORE;
    }
    assert(endptr == chunk_end);

    if((size_t)num_arcs > sizeof(s_arcs) / sizeof(s_arcs[0])) {
        arcs = (asn_oid_arc_t *)MALLOC(num_arcs * sizeof(arcs[0]));
        if(!arcs) return JPBD_SYSTEM_FAILURE;
        ret = OBJECT_IDENTIFIER_parse_arcs((const char *)chunk_buf, chunk_size,
                                           arcs, num_arcs, &endptr);
        if(ret != num_arcs) {
            return JPBD_SYSTEM_FAILURE;  /* assert?.. */
        }
    }

    /*
     * Convert arcs into BER representation.
     */
    ret = RELATIVE_OID_set_arcs(st, arcs, num_arcs);
    if(arcs != s_arcs) FREEMEM(arcs);

    return ret ? JPBD_SYSTEM_FAILURE : JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
RELATIVE_OID_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                        const asn_TYPE_descriptor_t *td, void **sptr,
                        const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td,
                                sptr, sizeof(RELATIVE_OID_t),
                                buf_ptr, size, RELATIVE_OID__jer_body_decode);
}

asn_enc_rval_t
RELATIVE_OID_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, enum jer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const RELATIVE_OID_t *st = (const RELATIVE_OID_t *)sptr;
    asn_enc_rval_t er = {0,0,0};
    ssize_t ro_encoded = 0;

    (void)ilevel;  /* Unused argument */
    (void)flags;  /* Unused argument */

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    ASN__CALLBACK("\"", 1);
    ro_encoded = RELATIVE_OID__dump_body(st, cb, app_key);
    if(ro_encoded < 0) goto cb_failed;
    er.encoded += ro_encoded;
    ASN__CALLBACK("\"", 1);

    ASN__ENCODED_OK(er);

cb_failed:
    ASN__ENCODE_FAILED;
}
