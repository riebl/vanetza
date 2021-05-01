/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NULL.h"

/*
 * Decode NULL type.
 */
asn_dec_rval_t
NULL_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **bool_value,
                const void *buf_ptr, size_t size, int tag_mode) {
    NULL_t *st = (NULL_t *)*bool_value;
    asn_dec_rval_t rval;
    ber_tlv_len_t length;

    if(st == NULL) {
        st = (NULL_t *)(*bool_value = CALLOC(1, sizeof(*st)));
        if(st == NULL) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }
    }

    ASN_DEBUG("Decoding %s as NULL (tm=%d)", td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size, tag_mode, 0,
                          &length, 0);
    if(rval.code != RC_OK) {
        return rval;
    }

    // X.690-201508, #8.8.2, length shall be zero.
    if(length != 0) {
        ASN_DEBUG("Decoding %s as NULL failed: too much data", td->name);
        rval.code = RC_FAIL;
        rval.consumed = 0;
        return rval;
    }

    return rval;
}

asn_enc_rval_t
NULL_encode_der(const asn_TYPE_descriptor_t *td, const void *ptr, int tag_mode,
                ber_tlv_tag_t tag, asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t erval = {0,0,0};

    erval.encoded = der_write_tags(td, 0, tag_mode, 0, tag, cb, app_key);
    if(erval.encoded == -1) {
        erval.failed_type = td;
        erval.structure_ptr = ptr;
    }

    ASN__ENCODED_OK(erval);
}
