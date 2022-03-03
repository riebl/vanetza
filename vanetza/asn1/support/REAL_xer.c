/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "REAL.h"

asn_enc_rval_t
REAL_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
                void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    asn_enc_rval_t er = {0,0,0};
    double d;

    (void)ilevel;

    if(!st || !st->buf || asn_REAL2double(st, &d))
        ASN__ENCODE_FAILED;

    er.encoded = REAL__dump(d, flags & XER_F_CANONICAL, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}

/*
 * Decode the chunk of XML text encoding REAL.
 */
static enum xer_pbd_rval
REAL__xer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                      const void *chunk_buf, size_t chunk_size) {
    REAL_t *st = (REAL_t *)sptr;
    double value;
    const char *xerdata = (const char *)chunk_buf;
    char *endptr = 0;
    char *b;

    (void)td;

    if(!chunk_size) return XPBD_BROKEN_ENCODING;

    /*
     * Decode an XMLSpecialRealValue: <MINUS-INFINITY>, etc.
     */
    if(xerdata[0] == 0x3c /* '<' */) {
        size_t i;
        for(i = 0; i < sizeof(specialRealValue) / sizeof(specialRealValue[0]); i++) {
            struct specialRealValue_s *srv = &specialRealValue[i];
            double dv;

            if(srv->length != chunk_size
            || memcmp(srv->string, chunk_buf, chunk_size))
                continue;

            /*
             * It could've been done using
             * (double)srv->dv / real_zero,
             * but it summons fp exception on some platforms.
             */
            switch(srv->dv) {
            case -1: dv = - INFINITY; break;
            case 0: dv = NAN;	break;
            case 1: dv = INFINITY;	break;
            default: return XPBD_SYSTEM_FAILURE;
            }

            if(asn_double2REAL(st, dv))
                return XPBD_SYSTEM_FAILURE;

            return XPBD_BODY_CONSUMED;
        }
        ASN_DEBUG("Unknown XMLSpecialRealValue");
        return XPBD_BROKEN_ENCODING;
    }

    /*
     * Copy chunk into the nul-terminated string, and run strtod.
     */
    b = (char *)MALLOC(chunk_size + 1);
    if(!b) return XPBD_SYSTEM_FAILURE;
    memcpy(b, chunk_buf, chunk_size);
    b[chunk_size] = 0;	/* nul-terminate */

    value = strtod(b, &endptr);
    FREEMEM(b);
    if(endptr == b) return XPBD_BROKEN_ENCODING;

    if(asn_double2REAL(st, value))
        return XPBD_SYSTEM_FAILURE;

    return XPBD_BODY_CONSUMED;
}

asn_dec_rval_t
REAL_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **sptr,
                const char *opt_mname, const void *buf_ptr, size_t size) {
    return xer_decode_primitive(opt_codec_ctx, td,
                                sptr, sizeof(REAL_t), opt_mname,
                                buf_ptr, size, REAL__xer_body_decode);
}
