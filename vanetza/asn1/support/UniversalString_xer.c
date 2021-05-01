/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "UniversalString.h"
#include "UTF8String.h"

asn_dec_rval_t
UniversalString_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                           const asn_TYPE_descriptor_t *td, void **sptr,
                           const char *opt_mname, const void *buf_ptr,
                           size_t size) {
    asn_dec_rval_t rc;

    rc = OCTET_STRING_decode_xer_utf8(opt_codec_ctx, td, sptr, opt_mname,
                                      buf_ptr, size);
    if(rc.code == RC_OK) {
        /*
         * Now we have a whole string in UTF-8 format.
         * Convert it into UCS-4.
         */
        uint32_t *wcs;
        size_t wcs_len;
        UTF8String_t *st;
#ifndef WORDS_BIGENDIAN
        int little_endian = 1;
#endif

        assert(*sptr);
        st = (UTF8String_t *)*sptr;
        assert(st->buf);
        wcs_len = UTF8String_to_wcs(st, 0, 0);

        wcs = (uint32_t *)MALLOC(4 * (wcs_len + 1));
        if(wcs == 0 || UTF8String_to_wcs(st, wcs, wcs_len) != wcs_len) {
            rc.code = RC_FAIL;
            rc.consumed = 0;
            return rc;
        } else {
            wcs[wcs_len] = 0;  /* nul-terminate */
        }

#ifndef WORDS_BIGENDIAN
        if(*(char *)&little_endian) {
            /* Swap byte order in encoding */
            uint32_t *wc = wcs;
            uint32_t *wc_end = wcs + wcs_len;
            for(; wc < wc_end; wc++) {
                /* *wc = htonl(*wc); */
                uint32_t wch = *wc;
                *((uint8_t *)wc + 0) = wch >> 24;
                *((uint8_t *)wc + 1) = wch >> 16;
                *((uint8_t *)wc + 2) = wch >> 8;
                *((uint8_t *)wc + 3) = wch;
            }
        }
#endif  /* WORDS_BIGENDIAN */

        FREEMEM(st->buf);
        st->buf = (uint8_t *)wcs;
        st->size = 4 * wcs_len;
    }
    return rc;
}

asn_enc_rval_t
UniversalString_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                           int ilevel, enum xer_encoder_flags_e flags,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    const UniversalString_t *st = (const UniversalString_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = UniversalString__dump(st, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
