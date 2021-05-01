/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "ANY.h"
#include <errno.h>

#undef RETURN
#define RETURN(_code)                       \
    do {                                    \
        asn_dec_rval_t tmprval;             \
        tmprval.code = _code;               \
        tmprval.consumed = consumed_myself; \
        return tmprval;                     \
    } while(0)

asn_dec_rval_t
ANY_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, void **sptr,
                asn_per_data_t *pd) {
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_ANY_specs;
    size_t consumed_myself = 0;
    int repeat;
    ANY_t *st = (ANY_t *)*sptr;

    (void)opt_codec_ctx;
    (void)constraints;

    /*
     * Allocate the structure.
     */
    if(!st) {
        st = (ANY_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) RETURN(RC_FAIL);
    }

    ASN_DEBUG("UPER Decoding ANY type");

    st->size = 0;
    do {
        ssize_t raw_len;
        ssize_t len_bytes;
        ssize_t len_bits;
        void *p;
        int ret;

        /* Get the PER length */
        raw_len = uper_get_length(pd, -1, 0, &repeat);
        if(raw_len < 0) RETURN(RC_WMORE);
        if(raw_len == 0 && st->buf) break;

        ASN_DEBUG("Got PER length len %" ASN_PRI_SIZE ", %s (%s)", raw_len,
                  repeat ? "repeat" : "once", td->name);
        len_bytes = raw_len;
        len_bits = len_bytes * 8;

        p = REALLOC(st->buf, st->size + len_bytes + 1);
        if(!p) RETURN(RC_FAIL);
        st->buf = (uint8_t *)p;

        ret = per_get_many_bits(pd, &st->buf[st->size], 0, len_bits);
        if(ret < 0) RETURN(RC_WMORE);
        consumed_myself += len_bits;
        st->size += len_bytes;
    } while(repeat);
    st->buf[st->size] = 0; /* nul-terminate */

    RETURN(RC_OK);
}

asn_enc_rval_t
ANY_encode_uper(const asn_TYPE_descriptor_t *td,
                const asn_per_constraints_t *constraints, const void *sptr,
                asn_per_outp_t *po) {
    const ANY_t *st = (const ANY_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};
    const uint8_t *buf;
    size_t size;
    int ret;

    (void)constraints;

    if(!st || (!st->buf && st->size)) ASN__ENCODE_FAILED;

    buf = st->buf;
    size = st->size;
    do {
        int need_eom = 0;
        ssize_t may_save = uper_put_length(po, size, &need_eom);
        if(may_save < 0) ASN__ENCODE_FAILED;

        ret = per_put_many_bits(po, buf, may_save * 8);
        if(ret) ASN__ENCODE_FAILED;

        buf += may_save;
        size -= may_save;
        assert(!(may_save & 0x07) || !size);
        if(need_eom && uper_put_length(po, 0, 0))
            ASN__ENCODE_FAILED; /* End of Message length */
    } while(size);

    ASN__ENCODED_OK(er);
}
