/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "OCTET_STRING.h"
#include "BIT_STRING.h"  /* for .bits_unused member */

#undef RETURN
#define RETURN(_code) do {\
        asn_dec_rval_t tmprval;\
        tmprval.code = _code;\
        tmprval.consumed = consumed_myself;\
        return tmprval;\
    } while(0)

static asn_per_constraints_t asn_DEF_OCTET_STRING_constraints = {
    { APC_CONSTRAINED, 8, 8, 0, 255 },
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },
    0, 0
};

asn_dec_rval_t
OCTET_STRING_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                         const asn_TYPE_descriptor_t *td,
                         const asn_per_constraints_t *constraints, void **sptr,
                         asn_per_data_t *pd) {
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    const asn_per_constraints_t *pc =
        constraints ? constraints : td->encoding_constraints.per_constraints;
    const asn_per_constraint_t *cval;
    const asn_per_constraint_t *csiz;
    asn_dec_rval_t rval = { RC_OK, 0 };
    OCTET_STRING_t *st = (OCTET_STRING_t *)*sptr;
    ssize_t consumed_myself = 0;
    int repeat;
    enum {
        OS__BPC_CHAR = 1,
        OS__BPC_U16 = 2,
        OS__BPC_U32 = 4
    } bpc;  /* Bytes per character */
    unsigned int unit_bits;
    unsigned int canonical_unit_bits;

    (void)opt_codec_ctx;

    if(pc) {
        cval = &pc->value;
        csiz = &pc->size;
    } else {
        cval = &asn_DEF_OCTET_STRING_constraints.value;
        csiz = &asn_DEF_OCTET_STRING_constraints.size;
    }

    switch(specs->subvariant) {
    default:
    case ASN_OSUBV_ANY:
    case ASN_OSUBV_BIT:
        ASN_DEBUG("Unrecognized subvariant %d", specs->subvariant);
        RETURN(RC_FAIL);
        break;
    case ASN_OSUBV_STR:
        canonical_unit_bits = unit_bits = 8;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_CHAR;
        break;
    case ASN_OSUBV_U16:
        canonical_unit_bits = unit_bits = 16;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_U16;
        break;
    case ASN_OSUBV_U32:
        canonical_unit_bits = unit_bits = 32;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_U32;
        break;
    }

    /*
     * Allocate the string.
     */
    if(!st) {
        st = (OCTET_STRING_t *)(*sptr = CALLOC(1, specs->struct_size));
        if(!st) RETURN(RC_FAIL);
    }

    ASN_DEBUG("PER Decoding %s size %ld .. %ld bits %d",
              csiz->flags & APC_EXTENSIBLE ? "extensible" : "non-extensible",
              csiz->lower_bound, csiz->upper_bound, csiz->effective_bits);

    if(csiz->flags & APC_EXTENSIBLE) {
        int inext = per_get_few_bits(pd, 1);
        if(inext < 0) RETURN(RC_WMORE);
        if(inext) {
            csiz = &asn_DEF_OCTET_STRING_constraints.size;
            unit_bits = canonical_unit_bits;
        }
    }

    if(csiz->effective_bits >= 0) {
        FREEMEM(st->buf);
        if(bpc) {
            st->size = csiz->upper_bound * bpc;
        } else {
            st->size = (csiz->upper_bound + 7) >> 3;
        }
        st->buf = (uint8_t *)MALLOC(st->size + 1);
        if(!st->buf) { st->size = 0; RETURN(RC_FAIL); }
    }

    /* X.691, #16.5: zero-length encoding */
    /* X.691, #16.6: short fixed length encoding (up to 2 octets) */
    /* X.691, #16.7: long fixed length encoding (up to 64K octets) */
    if(csiz->effective_bits == 0) {
        int ret;
        if(bpc) {
            ASN_DEBUG("Encoding OCTET STRING size %ld",
                      csiz->upper_bound);
            ret = OCTET_STRING_per_get_characters(pd, st->buf,
                                                  csiz->upper_bound,
                                                  bpc, unit_bits,
                                                  cval->lower_bound,
                                                  cval->upper_bound,
                                                  pc);
            if(ret > 0) RETURN(RC_FAIL);
        } else {
            ASN_DEBUG("Encoding BIT STRING size %ld",
                      csiz->upper_bound);
            ret = per_get_many_bits(pd, st->buf, 0,
                                    unit_bits * csiz->upper_bound);
        }
        if(ret < 0) RETURN(RC_WMORE);
        consumed_myself += unit_bits * csiz->upper_bound;
        st->buf[st->size] = 0;
        RETURN(RC_OK);
    }

    st->size = 0;
    do {
        ssize_t raw_len;
        ssize_t len_bytes;
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
        len_bytes = raw_len * bpc;
        p = REALLOC(st->buf, st->size + len_bytes + 1);
        if(!p) RETURN(RC_FAIL);
        st->buf = (uint8_t *)p;

        ret = OCTET_STRING_per_get_characters(pd, &st->buf[st->size], raw_len,
                                              bpc, unit_bits, cval->lower_bound,
                                              cval->upper_bound, pc);
        if(ret > 0) RETURN(RC_FAIL);
        if(ret < 0) RETURN(RC_WMORE);
        st->size += len_bytes;
    } while(repeat);
    st->buf[st->size] = 0;  /* nul-terminate */

    return rval;
}

asn_enc_rval_t
OCTET_STRING_encode_uper(const asn_TYPE_descriptor_t *td,
                         const asn_per_constraints_t *constraints,
                         const void *sptr, asn_per_outp_t *po) {
    const asn_OCTET_STRING_specifics_t *specs = td->specifics
        ? (const asn_OCTET_STRING_specifics_t *)td->specifics
        : &asn_SPC_OCTET_STRING_specs;
    const asn_per_constraints_t *pc = constraints
        ? constraints
        : td->encoding_constraints.per_constraints;
    const asn_per_constraint_t *cval;
    const asn_per_constraint_t *csiz;
    const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
    asn_enc_rval_t er = { 0, 0, 0 };
    int inext = 0;  /* Lies not within extension root */
    unsigned int unit_bits;
    unsigned int canonical_unit_bits;
    size_t size_in_units;
    const uint8_t *buf;
    int ret;
    enum {
        OS__BPC_CHAR = 1,
        OS__BPC_U16 = 2,
        OS__BPC_U32 = 4
    } bpc;  /* Bytes per character */
    int ct_extensible;

    if(!st || (!st->buf && st->size))
        ASN__ENCODE_FAILED;

    if(pc) {
        cval = &pc->value;
        csiz = &pc->size;
    } else {
        cval = &asn_DEF_OCTET_STRING_constraints.value;
        csiz = &asn_DEF_OCTET_STRING_constraints.size;
    }
    ct_extensible = csiz->flags & APC_EXTENSIBLE;

    switch(specs->subvariant) {
    default:
    case ASN_OSUBV_ANY:
    case ASN_OSUBV_BIT:
        ASN__ENCODE_FAILED;
    case ASN_OSUBV_STR:
        canonical_unit_bits = unit_bits = 8;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_CHAR;
        size_in_units = st->size;
        break;
    case ASN_OSUBV_U16:
        canonical_unit_bits = unit_bits = 16;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_U16;
        size_in_units = st->size >> 1;
        if(st->size & 1) {
            ASN_DEBUG("%s string size is not modulo 2", td->name);
            ASN__ENCODE_FAILED;
        }
        break;
    case ASN_OSUBV_U32:
        canonical_unit_bits = unit_bits = 32;
        if(cval->flags & APC_CONSTRAINED)
            unit_bits = cval->range_bits;
        bpc = OS__BPC_U32;
        size_in_units = st->size >> 2;
        if(st->size & 3) {
            ASN_DEBUG("%s string size is not modulo 4", td->name);
            ASN__ENCODE_FAILED;
        }
        break;
    }

    ASN_DEBUG("Encoding %s into %" ASN_PRI_SIZE " units of %d bits"
              " (%ld..%ld, effective %d)%s",
              td->name, size_in_units, unit_bits,
              csiz->lower_bound, csiz->upper_bound,
              csiz->effective_bits, ct_extensible ? " EXT" : "");

    /* Figure out whether size lies within PER visible constraint */

    if(csiz->effective_bits >= 0) {
        if((ssize_t)size_in_units < csiz->lower_bound
           || (ssize_t)size_in_units > csiz->upper_bound) {
            if(ct_extensible) {
                csiz = &asn_DEF_OCTET_STRING_constraints.size;
                unit_bits = canonical_unit_bits;
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
        ASN_DEBUG("Encoding %" ASN_PRI_SIZE " bytes (%ld), length in %d bits", st->size,
                  size_in_units - csiz->lower_bound, csiz->effective_bits);
        ret = per_put_few_bits(po, size_in_units - csiz->lower_bound,
                               csiz->effective_bits);
        if(ret) ASN__ENCODE_FAILED;
        ret = OCTET_STRING_per_put_characters(po, st->buf, size_in_units, bpc,
                                              unit_bits, cval->lower_bound,
                                              cval->upper_bound, pc);
        if(ret) ASN__ENCODE_FAILED;
        ASN__ENCODED_OK(er);
    }

    ASN_DEBUG("Encoding %" ASN_PRI_SIZE " bytes", st->size);

    buf = st->buf;
    ASN_DEBUG("Encoding %" ASN_PRI_SIZE " in units", size_in_units);
    do {
        int need_eom = 0;
        ssize_t may_save = uper_put_length(po, size_in_units, &need_eom);
        if(may_save < 0) ASN__ENCODE_FAILED;

        ASN_DEBUG("Encoding %" ASN_PRI_SSIZE " of %" ASN_PRI_SIZE "%s", may_save, size_in_units,
                  need_eom ? ",+EOM" : "");

        ret = OCTET_STRING_per_put_characters(po, buf, may_save, bpc, unit_bits,
                                              cval->lower_bound,
                                              cval->upper_bound, pc);
        if(ret) ASN__ENCODE_FAILED;

        buf += may_save * bpc;
        size_in_units -= may_save;
        assert(!(may_save & 0x07) || !size_in_units);
        if(need_eom && uper_put_length(po, 0, 0))
            ASN__ENCODE_FAILED; /* End of Message length */
    } while(size_in_units);

    ASN__ENCODED_OK(er);
}
