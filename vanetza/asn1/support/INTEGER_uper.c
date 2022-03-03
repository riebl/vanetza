/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "INTEGER.h"

asn_dec_rval_t
INTEGER_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints, void **sptr,
                    asn_per_data_t *pd) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_dec_rval_t rval = { RC_OK, 0 };
    INTEGER_t *st = (INTEGER_t *)*sptr;
    const asn_per_constraint_t *ct;
    int repeat;

    (void)opt_codec_ctx;

    if(!st) {
        st = (INTEGER_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;

    if(ct && ct->flags & APC_EXTENSIBLE) {
        int inext = per_get_few_bits(pd, 1);
        if(inext < 0) ASN__DECODE_STARVED;
        if(inext) ct = 0;
    }

    FREEMEM(st->buf);
    st->buf = 0;
    st->size = 0;
    if(ct) {
        if(ct->flags & APC_SEMI_CONSTRAINED) {
            st->buf = (uint8_t *)CALLOC(1, 2);
            if(!st->buf) ASN__DECODE_FAILED;
            st->size = 1;
        } else if(ct->flags & APC_CONSTRAINED && ct->range_bits >= 0) {
            size_t size = (ct->range_bits + 7) >> 3;
            st->buf = (uint8_t *)MALLOC(1 + size + 1);
            if(!st->buf) ASN__DECODE_FAILED;
            st->size = size;
        }
    }

    /* X.691-2008/11, #13.2.2, constrained whole number */
    if(ct && ct->flags != APC_UNCONSTRAINED) {
        /* #11.5.6 */
        ASN_DEBUG("Integer with range %d bits", ct->range_bits);
        if(ct->range_bits >= 0) {
            if((size_t)ct->range_bits > 8 * sizeof(uintmax_t))
                ASN__DECODE_FAILED;

            if(specs && specs->field_unsigned) {
                uintmax_t uvalue = 0;
                if(uper_get_constrained_whole_number(pd,
                    &uvalue, ct->range_bits))
                    ASN__DECODE_STARVED;
                ASN_DEBUG("Got value %lu + low %ld",
                    uvalue, ct->lower_bound);
                uvalue += ct->lower_bound;
                if(asn_umax2INTEGER(st, uvalue))
                    ASN__DECODE_FAILED;
            } else {
                uintmax_t uvalue = 0;
                intmax_t svalue;
                if(uper_get_constrained_whole_number(pd,
                    &uvalue, ct->range_bits))
                    ASN__DECODE_STARVED;
                ASN_DEBUG("Got value %lu + low %ld",
                uvalue, ct->lower_bound);
                if(per_imax_range_unrebase(uvalue, ct->lower_bound,
                                           ct->upper_bound, &svalue)
                   || asn_imax2INTEGER(st, svalue)) {
                    ASN__DECODE_FAILED;
                }
            }
            return rval;
        }
    } else {
        ASN_DEBUG("Decoding unconstrained integer %s", td->name);
    }

    /* X.691, #12.2.3, #12.2.4 */
    do {
        ssize_t len = 0;
        void *p = NULL;
        int ret = 0;

        /* Get the PER length */
        len = uper_get_length(pd, -1, 0, &repeat);
        if(len < 0) ASN__DECODE_STARVED;

        p = REALLOC(st->buf, st->size + len + 1);
        if(!p) ASN__DECODE_FAILED;
        st->buf = (uint8_t *)p;

        ret = per_get_many_bits(pd, &st->buf[st->size], 0, 8 * len);
        if(ret < 0) ASN__DECODE_STARVED;
        st->size += len;
    } while(repeat);
    st->buf[st->size] = 0;  /* JIC */

    /* #12.2.3 */
    if(ct && ct->lower_bound) {
        /*
         * TODO: replace by in-place arithmetic.
         */
        long value = 0;
        if(asn_INTEGER2long(st, &value))
            ASN__DECODE_FAILED;
        if(asn_imax2INTEGER(st, value + ct->lower_bound))
            ASN__DECODE_FAILED;
    }

    return rval;
}

asn_enc_rval_t
INTEGER_encode_uper(const asn_TYPE_descriptor_t *td,
                    const asn_per_constraints_t *constraints, const void *sptr,
                    asn_per_outp_t *po) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    const uint8_t *buf;
    const uint8_t *end;
    const asn_per_constraint_t *ct;
    union {
        intmax_t s;
        uintmax_t u;
    } value;

    if(!st || st->size == 0) ASN__ENCODE_FAILED;

    if(!constraints) constraints = td->encoding_constraints.per_constraints;
    ct = constraints ? &constraints->value : 0;

    er.encoded = 0;

    if(ct) {
        int inext = 0;
        if(specs && specs->field_unsigned) {
            if(asn_INTEGER2umax(st, &value.u))
                ASN__ENCODE_FAILED;
            /* Check proper range */
            if(ct->flags & APC_SEMI_CONSTRAINED) {
                if(value.u < (uintmax_t)ct->lower_bound)
                    inext = 1;
            } else if(ct->range_bits >= 0) {
                if(value.u < (uintmax_t)ct->lower_bound
                || value.u > (uintmax_t)ct->upper_bound)
                    inext = 1;
            }
            ASN_DEBUG("Value %lu (%02x/%" ASN_PRI_SIZE ") lb %lu ub %lu %s",
                      value.u, st->buf[0], st->size,
                      ct->lower_bound, ct->upper_bound,
                      inext ? "ext" : "fix");
        } else {
            if(asn_INTEGER2imax(st, &value.s))
                ASN__ENCODE_FAILED;
            /* Check proper range */
            if(ct->flags & APC_SEMI_CONSTRAINED) {
                if(value.s < ct->lower_bound)
                    inext = 1;
            } else if(ct->range_bits >= 0) {
                if(value.s < ct->lower_bound
                || value.s > ct->upper_bound)
                    inext = 1;
            }
            ASN_DEBUG("Value %ld (%02x/%" ASN_PRI_SIZE ") lb %ld ub %ld %s",
                      value.s, st->buf[0], st->size,
                      ct->lower_bound, ct->upper_bound,
                      inext ? "ext" : "fix");
        }
        if(ct->flags & APC_EXTENSIBLE) {
            if(per_put_few_bits(po, inext, 1))
                ASN__ENCODE_FAILED;
            if(inext) ct = 0;
        } else if(inext) {
            ASN__ENCODE_FAILED;
        }
    }

    /* X.691-11/2008, #13.2.2, test if constrained whole number */
    if(ct && ct->range_bits >= 0) {
        uintmax_t v;
        /* #11.5.6 -> #11.3 */
        if(specs && specs->field_unsigned) {
            if(((uintmax_t)ct->lower_bound > (uintmax_t)(ct->upper_bound)
            || (value.u < (uintmax_t)ct->lower_bound))
            || (value.u > (uintmax_t)ct->upper_bound)) {
                ASN_DEBUG("Value %lu to-be-encoded is outside the bounds [%lu, %lu]!",
                          value.u, ct->lower_bound, ct->upper_bound);
                ASN__ENCODE_FAILED;
            }
            v = value.u - (uintmax_t)ct->lower_bound;
        } else {
            if(per_imax_range_rebase(value.s, ct->lower_bound, ct->upper_bound, &v)) {
                ASN__ENCODE_FAILED;
            }
        }
        ASN_DEBUG("Encoding integer %lu with range %d bits",
                  v, ct->range_bits);
        if(uper_put_constrained_whole_number_u(po, v, ct->range_bits))
            ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }

    if(ct && ct->lower_bound) {
        ASN_DEBUG("Adjust lower bound to %ld", ct->lower_bound);
        /* TODO: adjust lower bound */
        ASN__ENCODE_FAILED;
    }

    for(buf = st->buf, end = st->buf + st->size; buf < end;) {
        int need_eom = 0;
        ssize_t mayEncode = uper_put_length(po, end - buf, &need_eom);
        if(mayEncode < 0)
            ASN__ENCODE_FAILED;
        if(per_put_many_bits(po, buf, 8 * mayEncode))
            ASN__ENCODE_FAILED;
        buf += mayEncode;
        if(need_eom && uper_put_length(po, 0, 0)) ASN__ENCODE_FAILED;
    }

    ASN__ENCODED_OK(er);
}
