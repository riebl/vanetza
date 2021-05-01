/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"

/*
 * Decode the chunk of XML text encoding REAL.
 */
asn_dec_rval_t
NativeReal_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td, void **sptr,
                      const char *opt_mname, const void *buf_ptr, size_t size) {
    asn_dec_rval_t rval;
    REAL_t st = { 0, 0 };
    REAL_t *stp = &st;

    rval = REAL_decode_xer(opt_codec_ctx, td, (void **)&stp, opt_mname,
                           buf_ptr, size);
    if(rval.code == RC_OK) {
        double d;
        if(asn_REAL2double(&st, &d) || NativeReal__set(td, sptr, d) < 0) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
        }
    } else {
        /* Convert all errors into RC_FAIL */
        rval.consumed = 0;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &st);
    return rval;
}

asn_enc_rval_t
NativeReal_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, enum xer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    double d = NativeReal__get_double(td, sptr);
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;

    er.encoded = REAL__dump(d, flags & XER_F_CANONICAL, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
