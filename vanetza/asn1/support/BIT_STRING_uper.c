/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "BIT_STRING.h"

#undef  RETURN
#define RETURN(_code)                       \
    do {                                    \
        asn_dec_rval_t tmprval;             \
        tmprval.code = _code;               \
        tmprval.consumed = consumed_myself; \
        return tmprval;                     \
    } while(0)

static asn_per_constraint_t asn_DEF_BIT_STRING_constraint_size = {
    APC_SEMI_CONSTRAINED, -1, -1, 0, 0};

asn_dec_rval_t
BIT_STRING_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints, void **sptr,
                       asn_per_data_t *pd) {
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_BIT_STRING_specs;
    const asn_per_constraints_t *pc =
        constraints ? constraints : td->encoding_constraints.per_constraints;
    const asn_per_constraint_t *csiz;
    asn_dec_rval_t rval = { RC_OK, 0 };
    BIT_STRING_t *st = (BIT_STRING_t *)*sptr;
    ssize_t consumed_myself = 0;
    int repeat;

    (void)opt_codec_ctx;

    if(pc) {
        csiz = &pc->size;
    } else {
        csiz = &asn_DEF_BIT_STRING_constraint_size;
    }

    if(specs->subvariant != ASN_OSUBV_BIT) {
        ASN_DEBUG("Subvariant %d is not BIT OSUBV_BIT", specs->subvariant);
        RETURN(RC_FAIL);
    }

    /*
     * Allocate the string.
     */
    if(!st) {
        st = (BIT_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) RETURN(RC_FAIL);
    }

    ASN_DEBUG("PER Decoding %s size %ld .. %ld bits %d",
        csiz->flags & APC_EXTENSIBLE ? "extensible" : "non-extensible",
        csiz->lower_bound, csiz->upper_bound, csiz->effective_bits);

    if(csiz->flags & APC_EXTENSIBLE) {
        int inext = per_get_few_bits(pd, 1);
        if(inext < 0) RETURN(RC_WMORE);
        if(inext) {
            csiz = &asn_DEF_BIT_STRING_constraint_size;
        }
    }

    if(csiz->effective_bits >= 0) {
        FREEMEM(st->buf);
        st->size = (csiz->upper_bound + 7) >> 3;
        st->buf = (uint8_t *)MALLOC(st->size + 1);
        if(!st->buf) { st->size = 0; RETURN(RC_FAIL); }
    }

    /* X.691, #16.5: zero-length encoding */
    /* X.691, #16.6: short fixed length encoding (up to 2 octets) */
    /* X.691, #16.7: long fixed length encoding (up to 64K octets) */
    if(csiz->effective_bits == 0) {
        int ret;
        ASN_DEBUG("Encoding BIT STRING size %ld", csiz->upper_bound);
        ret = per_get_many_bits(pd, st->buf, 0, csiz->upper_bound);
        if(ret < 0) RETURN(RC_WMORE);
        consumed_myself += csiz->upper_bound;
        st->buf[st->size] = 0;
        st->bits_unused = (8 - (csiz->upper_bound & 0x7)) & 0x7;
        RETURN(RC_OK);
    }

    st->size = 0;
    do {
        ssize_t raw_len;
        ssize_t len_bytes;
        ssize_t len_bits;
        void *p;
        int ret;

        /* Get the PER length */
        raw_len = uper_get_length(pd, csiz->effective_bits, csiz->lower_bound,
                                  &repeat);
        if(raw_len < 0) RETURN(RC_WMORE);
        if(raw_len == 0 && st->buf) break;

        ASN_DEBUG("Got PER length eb %ld, len %ld, %s (%s)",
            (long)csiz->effective_bits, (long)raw_len,
            repeat ? "repeat" : "once", td->name);
        len_bits = raw_len;
        len_bytes = (len_bits + 7) >> 3;
        if(len_bits & 0x7) st->bits_unused = 8 - (len_bits & 0x7);
        /* len_bits be multiple of 16K if repeat is set */
        p = REALLOC(st->buf, st->size + len_bytes + 1);
        if(!p) RETURN(RC_FAIL);
        st->buf = (uint8_t *)p;

        ret = per_get_many_bits(pd, &st->buf[st->size], 0, len_bits);
        if(ret < 0) RETURN(RC_WMORE);
        st->size += len_bytes;
    } while(repeat);
    st->buf[st->size] = 0;  /* nul-terminate */

    return rval;
}

asn_enc_rval_t
BIT_STRING_encode_uper(const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints,
                       const void *sptr, asn_per_outp_t *po) {
    const asn_OCTET_STRING_specifics_t *specs =
        td->specifics ? (const asn_OCTET_STRING_specifics_t *)td->specifics
                      : &asn_SPC_BIT_STRING_specs;
    const asn_per_constraints_t *pc =
        constraints ? constraints : td->encoding_constraints.per_constraints;
    const asn_per_constraint_t *csiz;
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    BIT_STRING_t compact_bstr;  /* Do not modify this directly! */
    asn_enc_rval_t er = { 0, 0, 0 };
    int inext = 0;  /* Lies not within extension root */
    size_t size_in_bits;
    const uint8_t *buf;
    int ret;
    int ct_extensible;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    if(specs->subvariant == ASN_OSUBV_BIT) {
        if((st->size == 0 && st->bits_unused) || (st->bits_unused & ~7))
            ASN__ENCODE_FAILED;
    } else {
        ASN__ENCODE_FAILED;
    }

    if(pc) {
        csiz = &pc->size;
    } else {
        csiz = &asn_DEF_BIT_STRING_constraint_size;
    }
    ct_extensible = csiz->flags & APC_EXTENSIBLE;

    /* Figure out the size without the trailing bits */
    st = BIT_STRING__compactify(st, &compact_bstr);
    size_in_bits = 8 * st->size - st->bits_unused;

    ASN_DEBUG(
        "Encoding %s into %" ASN_PRI_SIZE " bits"
        " (%ld..%ld, effective %d)%s",
        td->name, size_in_bits, csiz->lower_bound, csiz->upper_bound,
        csiz->effective_bits, ct_extensible ? " EXT" : "");

    /* Figure out whether size lies within PER visible constraint */

    if(csiz->effective_bits >= 0) {
        if((ssize_t)size_in_bits > csiz->upper_bound) {
            if(ct_extensible) {
                csiz = &asn_DEF_BIT_STRING_constraint_size;
                inext = 1;
            } else {
                ASN__ENCODE_FAILED;
            }
        }
    } else {
        inext = 0;
    }

    if(ct_extensible) {
        /* Declare whether length is [not] within extension root */
        if(per_put_few_bits(po, inext, 1))
            ASN__ENCODE_FAILED;
    }

    if(csiz->effective_bits >= 0 && !inext) {
        int add_trailer = (ssize_t)size_in_bits < csiz->lower_bound;
        ASN_DEBUG(
            "Encoding %" ASN_PRI_SIZE " bytes (%ld), length (in %d bits) trailer %d; actual "
            "value %" ASN_PRI_SSIZE "",
            st->size, size_in_bits - csiz->lower_bound, csiz->effective_bits,
            add_trailer,
            add_trailer ? 0 : (ssize_t)size_in_bits - csiz->lower_bound);
        ret = per_put_few_bits(
            po, add_trailer ? 0 : (ssize_t)size_in_bits - csiz->lower_bound,
            csiz->effective_bits);
        if(ret) ASN__ENCODE_FAILED;
        ret = per_put_many_bits(po, st->buf, size_in_bits);
        if(ret) ASN__ENCODE_FAILED;
        if(add_trailer) {
            static const uint8_t zeros[16];
            size_t trailing_zero_bits = csiz->lower_bound - size_in_bits;
            while(trailing_zero_bits > 0) {
                if(trailing_zero_bits > 8 * sizeof(zeros)) {
                    ret = per_put_many_bits(po, zeros, 8 * sizeof(zeros));
                    trailing_zero_bits -= 8 * sizeof(zeros);
                } else {
                    ret = per_put_many_bits(po, zeros, trailing_zero_bits);
                    trailing_zero_bits = 0;
                }
                if(ret) ASN__ENCODE_FAILED;
            }
        }
        ASN__ENCODED_OK(er);
    }

    ASN_DEBUG("Encoding %" ASN_PRI_SIZE " bytes", st->size);

    buf = st->buf;
    do {
        int need_eom = 0;
        ssize_t maySave = uper_put_length(po, size_in_bits, &need_eom);
        if(maySave < 0) ASN__ENCODE_FAILED;

        ASN_DEBUG("Encoding %" ASN_PRI_SSIZE " of %" ASN_PRI_SIZE "", maySave, size_in_bits);

        ret = per_put_many_bits(po, buf, maySave);
        if(ret) ASN__ENCODE_FAILED;

        buf += maySave >> 3;
        size_in_bits -= maySave;
        assert(!(maySave & 0x07) || !size_in_bits);
        if(need_eom && uper_put_length(po, 0, 0))
            ASN__ENCODE_FAILED; /* End of Message length */
    } while(size_in_bits);

    ASN__ENCODED_OK(er);
}
