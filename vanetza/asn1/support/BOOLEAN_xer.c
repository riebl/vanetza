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
 * Decode the chunk of XML text encoding INTEGER.
 */
static enum xer_pbd_rval
BOOLEAN__xer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    BOOLEAN_t *st = (BOOLEAN_t *)sptr;
    const char *p = (const char *)chunk_buf;

    (void)td;

    if(chunk_size && p[0] == 0x3c /* '<' */) {
        switch(xer_check_tag(chunk_buf, chunk_size, "false")) {
        case XCT_BOTH:
            /* "<false/>" */
            *st = 0;
            break;
        case XCT_UNKNOWN_BO:
            if(xer_check_tag(chunk_buf, chunk_size, "true") != XCT_BOTH)
                return XPBD_BROKEN_ENCODING;
            /* "<true/>" */
            *st = 1;  /* Or 0xff as in DER?.. */
            break;
        default:
            return XPBD_BROKEN_ENCODING;
        }
        return XPBD_BODY_CONSUMED;
    } else {
        return XPBD_BROKEN_ENCODING;
    }
}


asn_dec_rval_t
BOOLEAN_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **sptr,
                   const char *opt_mname, const void *buf_ptr, size_t size) {
    return xer_decode_primitive(opt_codec_ctx, td,
                                sptr, sizeof(BOOLEAN_t), opt_mname, buf_ptr, size,
                                BOOLEAN__xer_body_decode);
}

asn_enc_rval_t
BOOLEAN_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum xer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};

    (void)ilevel;
    (void)flags;

    if(!st) ASN__ENCODE_FAILED;

    if(*st) {
        ASN__CALLBACK("<true/>", 7);
    } else {
        ASN__CALLBACK("<false/>", 8);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
