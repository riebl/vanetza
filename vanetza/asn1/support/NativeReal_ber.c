/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"

/*
 * Decode REAL type.
 */
asn_dec_rval_t
NativeReal_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td, void **sptr,
                      const void *buf_ptr, size_t size, int tag_mode) {
    asn_dec_rval_t rval;
    ber_tlv_len_t length;

    ASN_DEBUG("Decoding %s as REAL (tm=%d)", td->name, tag_mode);

    /*
     * Check tags.
     */
    rval = ber_check_tags(opt_codec_ctx, td, 0, buf_ptr, size, tag_mode, 0,
                          &length, 0);
    if(rval.code != RC_OK) return rval;
    assert(length >= 0);    /* Ensured by ber_check_tags */

    ASN_DEBUG("%s length is %d bytes", td->name, (int)length);

    /*
     * Make sure we have this length.
     */
    buf_ptr = ((const char *)buf_ptr) + rval.consumed;
    size -= rval.consumed;
    if(length > (ber_tlv_len_t)size) {
        rval.code = RC_WMORE;
        rval.consumed = 0;
        return rval;
    }

    /*
     * ASN.1 encoded REAL: buf_ptr, length
     * Fill the Dbl, at the same time checking for overflow.
     * If overflow occurred, return with RC_FAIL.
     */
    {
        uint8_t scratch[24]; /* Longer than %.16f in decimal */
        REAL_t tmp;
        double d;
        int ret;

        if((size_t)length < sizeof(scratch)) {
            tmp.buf = scratch;
            tmp.size = length;
        } else {
            /* This rarely happens: impractically long value */
            tmp.buf = CALLOC(1, length + 1);
            tmp.size = length;
            if(!tmp.buf) {
                rval.code = RC_FAIL;
                rval.consumed = 0;
                return rval;
            }
        }

        memcpy(tmp.buf, buf_ptr, length);
        tmp.buf[length] = '\0';

        ret = asn_REAL2double(&tmp, &d);
        if(tmp.buf != scratch) FREEMEM(tmp.buf);
        if(ret) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
            return rval;
        }

        if(NativeReal__set(td, sptr, d) < 0)
            ASN__DECODE_FAILED;
    }

    rval.code = RC_OK;
    rval.consumed += length;

    ASN_DEBUG("Took %ld/%ld bytes to encode %s", (long)rval.consumed,
              (long)length, td->name);

    return rval;
}

/*
 * Encode the NativeReal using the standard REAL type DER encoder.
 */
asn_enc_rval_t
NativeReal_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int tag_mode, ber_tlv_tag_t tag,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    double d = NativeReal__get_double(td, sptr);
    asn_enc_rval_t erval = {0,0,0};
    REAL_t tmp;

    /* Prepare a temporary clean structure */
    memset(&tmp, 0, sizeof(tmp));

    if(asn_double2REAL(&tmp, d))
        ASN__ENCODE_FAILED;

    /* Encode a fake REAL */
    erval = der_encode_primitive(td, &tmp, tag_mode, tag, cb, app_key);
    if(erval.encoded == -1) {
        assert(erval.structure_ptr == &tmp);
        erval.structure_ptr = sptr;
    }

    /* Free possibly allocated members of the temporary structure */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);

    return erval;
}
