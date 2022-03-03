/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "BOOLEAN.h"

/*
 * Decode BOOLEAN type.
 */
asn_dec_rval_t
BOOLEAN_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **bool_value,
                   const void *buf_ptr, size_t size, int tag_mode) {
    BOOLEAN_t *st = (BOOLEAN_t *)*bool_value;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;
    ber_tlv_len_t lidx;

    if(st == NULL) {
        st = (BOOLEAN_t *)(*bool_value = CALLOC(1, sizeof(*st)));
        if(st == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Decoding %s as BOOLEAN (tm=%d)",
            td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size,
        tag_mode, 0, &length, 0);
    if(rval.code != RC_OK)
        return rval;

    ASN_DEBUG("Boolean length is %d bytes", (int)length);

    buf_ptr = ((const char *)buf_ptr) + rval.consumed;
    size -= rval.consumed;
    if(length > (ber_tlv_len_t)size) {
        rval.code = RC_WMORE;
        rval.consumed = 0;
        return rval;
    }

    /*
     * Compute boolean value.
     */
    for(*st = 0, lidx = 0;
        (lidx < length) && *st == 0; lidx++) {
        /*
         * Very simple approach: read bytes until the end or
         * value is already TRUE.
         * BOOLEAN is not supposed to contain meaningful data anyway.
         */
        *st |= ((const uint8_t *)buf_ptr)[lidx];
    }

    rval.code = RC_OK;
    rval.consumed += length;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s, value=%d",
        (long)rval.consumed, (long)length,
        td->name, *st);

    return rval;
}

asn_enc_rval_t
BOOLEAN_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int tag_mode, ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb,
                   void *app_key) {
    asn_enc_rval_t erval = {0,0,0};
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;

    erval.encoded = der_write_tags(td, 1, tag_mode, 0, tag, cb, app_key);
    if(erval.encoded == -1) {
        erval.failed_type = td;
        erval.structure_ptr = sptr;
        return erval;
    }

    if(cb) {
        uint8_t bool_value;

        bool_value = *st ? 0xff : 0; /* 0xff mandated by DER */

        if(cb(&bool_value, 1, app_key) < 0) {
            erval.encoded = -1;
            erval.failed_type = td;
            erval.structure_ptr = sptr;
            return erval;
        }
    }

    erval.encoded += 1;

    ASN__ENCODED_OK(erval);
}
