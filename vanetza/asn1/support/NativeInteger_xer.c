/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeInteger.h"

/*
 * Decode the chunk of XML text encoding INTEGER.
 */
asn_dec_rval_t
NativeInteger_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td, void **sptr,
                         const char *opt_mname, const void *buf_ptr,
                         size_t size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval;
    INTEGER_t st;
    void *st_ptr = (void *)&st;
    long *native = (long *)*sptr;

    if(!native) {
        native = (long *)(*sptr = CALLOC(1, sizeof(*native)));
        if(!native) ASN__DECODE_FAILED;
    }

    memset(&st, 0, sizeof(st));
    rval = INTEGER_decode_xer(opt_codec_ctx, td, &st_ptr,
                              opt_mname, buf_ptr, size);
    if(rval.code == RC_OK) {
        long l;
        if((specs&&specs->field_unsigned)
            ? asn_INTEGER2ulong(&st, (unsigned long *)&l) /* sic */
            : asn_INTEGER2long(&st, &l)) {
            rval.code = RC_FAIL;
            rval.consumed = 0;
        } else {
            *native = l;
        }
    } else {
        /*
         * Cannot restart from the middle;
         * there is no place to save state in the native type.
         * Request a continuation from the very beginning.
         */
        rval.consumed = 0;
    }
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &st);
    return rval;
}


asn_enc_rval_t
NativeInteger_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                         int ilevel, enum xer_encoder_flags_e flags,
                         asn_app_consume_bytes_f *cb, void *app_key) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    char scratch[32];  /* Enough for 64-bit int */
    asn_enc_rval_t er = {0,0,0};
    const long *native = (const long *)sptr;

    (void)ilevel;
    (void)flags;

    if(!native) ASN__ENCODE_FAILED;

    er.encoded = snprintf(scratch, sizeof(scratch),
                          (specs && specs->field_unsigned)
                              ? "%lu" : "%ld", *native);
    if(er.encoded <= 0 || (size_t)er.encoded >= sizeof(scratch)
        || cb(scratch, er.encoded, app_key) < 0)
        ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
