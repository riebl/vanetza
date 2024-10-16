/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "INTEGER.h"

struct je2v_key {
    const char *start;
    const char *stop;
    const asn_INTEGER_enum_map_t *vemap;
    const unsigned int *evmap;
};

static int
INTEGER_jer_st_prealloc(INTEGER_t *st, int min_size) {
    void *p = MALLOC(min_size + 1);
    if(p) {
        void *b = st->buf;
        st->size = 0;
        st->buf = p;
        FREEMEM(b);
        return 0;
    } else {
        return -1;
    }
}
/*
 * Decode the chunk of JSON text encoding INTEGER.
 */
static enum jer_pbd_rval
INTEGER__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    INTEGER_t *st = (INTEGER_t *)sptr;
    intmax_t dec_value;
    const char *lp;
    const char *lstart = (const char *)chunk_buf;
    const char *lstop = lstart + chunk_size;
    enum {
        ST_LEADSPACE,
        ST_WAITDIGITS,
        ST_DIGITS,
        ST_ZERO,
        ST_DIGITS_TRAILSPACE,
        ST_UNEXPECTED
    } state = ST_LEADSPACE;
    const char *dec_value_start = 0; /* INVARIANT: always !0 in ST_DIGITS */
    const char *dec_value_end = 0;

    if(chunk_size)
        ASN_DEBUG("INTEGER body %ld 0x%2x..0x%2x",
                  (long)chunk_size, *lstart, lstop[-1]);

    if(INTEGER_jer_st_prealloc(st, (chunk_size/3) + 1))
        return JPBD_SYSTEM_FAILURE;

    /*
     * We may have received a tag here. It will be processed inline.
     * Use strtoul()-like code and serialize the result.
     */
    for(lp = lstart; lp < lstop; lp++) {
        int lv = *lp;
        switch(lv) {
        case 0x09: case 0x0a: case 0x0d: case 0x20:
            switch(state) {
            case ST_LEADSPACE:
            case ST_DIGITS_TRAILSPACE:
                continue;
            case ST_DIGITS:
            case ST_ZERO:
                dec_value_end = lp;
                state = ST_DIGITS_TRAILSPACE;
                continue;
            default:
                break;
            }
            break;
        case 0x2d:  /* '-' */
            if(state == ST_LEADSPACE) {
                dec_value = 0;
                dec_value_start = lp;
                state = ST_WAITDIGITS;
                continue;
            }
            break;
        case 0x30: /* 0 */
            switch(state) {
            case ST_DIGITS: continue;
            case ST_LEADSPACE:
            case ST_WAITDIGITS:
                dec_value = 0;
                dec_value_start = lp;
                state = ST_ZERO;
                continue;
            case ST_ZERO: /* forbidden leading zero */
                return JPBD_BROKEN_ENCODING;
            default:
                break;
            }
            break;
        /* [1-9] */
        case 0x31: case 0x32: case 0x33: case 0x34:
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
            switch(state) {
            case ST_DIGITS: continue;
            case ST_LEADSPACE:
                dec_value = 0;
                dec_value_start = lp;
                /* FALL THROUGH */
            case ST_WAITDIGITS:
                state = ST_DIGITS;
                continue;
            case ST_ZERO: /* forbidden leading zero */
                return JPBD_BROKEN_ENCODING;
            default:
                break;
            }
            break;
        }

        /* Found extra non-numeric stuff */
        ASN_DEBUG("INTEGER :: Found non-numeric 0x%2x at %ld",
                  lv, (long)(lp - lstart));
        state = ST_UNEXPECTED;
        break;
    }

    switch(state) {
    case ST_DIGITS:
    case ST_ZERO:
        dec_value_end = lstop;
        /* FALL THROUGH */
    case ST_DIGITS_TRAILSPACE:
        /* The last symbol encountered was a digit. */
        switch(asn_strtoimax_lim(dec_value_start, &dec_value_end, &dec_value)) {
        case ASN_STRTOX_OK:
            if(specs && specs->field_unsigned && (uintmax_t) dec_value <= ULONG_MAX) {
                break;
            } else if(dec_value >= LONG_MIN && dec_value <= LONG_MAX) {
                break;
            } else {
                /*
                 * We model INTEGER on long for JER,
                 * to avoid rewriting all the tests at once.
                 */
                ASN_DEBUG("INTEGER exceeds long range");
            }
            /* Fall through */
        case ASN_STRTOX_ERROR_RANGE:
            ASN_DEBUG("INTEGER decode %s hit range limit", td->name);
            return JPBD_DECODER_LIMIT;
        case ASN_STRTOX_ERROR_INVAL:
        case ASN_STRTOX_EXPECT_MORE:
        case ASN_STRTOX_EXTRA_DATA:
            return JPBD_BROKEN_ENCODING;
        }
        break;
    case ST_LEADSPACE:
        /* Content not found */
        return JPBD_NOT_BODY_IGNORE;
    case ST_WAITDIGITS:
    case ST_UNEXPECTED:
        ASN_DEBUG("INTEGER: No useful digits (state %d)", state);
        return JPBD_BROKEN_ENCODING;  /* No digits */
    }

    /*
     * Convert the result of parsing of enumeration or a straight
     * decimal value into a BER representation.
     */
    if(asn_imax2INTEGER(st, dec_value)) {
                ASN_DEBUG("INTEGER decode %s conversion failed", td->name);
        return JPBD_SYSTEM_FAILURE;
        }

    return JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
INTEGER_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints,
                   void **sptr, const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(INTEGER_t),
        buf_ptr, size, INTEGER__jer_body_decode);
}


asn_enc_rval_t
INTEGER_encode_jer(const asn_TYPE_descriptor_t *td,
                   const asn_jer_constraints_t *constraints,
                   const void *sptr, int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const INTEGER_t *st = (const INTEGER_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = INTEGER__dump(td, st, cb, app_key, 1);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
