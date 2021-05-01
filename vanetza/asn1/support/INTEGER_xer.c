/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "INTEGER.h"

struct e2v_key {
    const char *start;
    const char *stop;
    const asn_INTEGER_enum_map_t *vemap;
    const unsigned int *evmap;
};
static int
INTEGER__compar_enum2value(const void *kp, const void *am) {
    const struct e2v_key *key = (const struct e2v_key *)kp;
    const asn_INTEGER_enum_map_t *el = (const asn_INTEGER_enum_map_t *)am;
    const char *ptr, *end, *name;

    /* Remap the element (sort by different criterion) */
    el = key->vemap + key->evmap[el - key->vemap];

    /* Compare strings */
    for(ptr = key->start, end = key->stop, name = el->enum_name;
            ptr < end; ptr++, name++) {
        if(*ptr != *name || !*name)
            return *(const unsigned char *)ptr - *(const unsigned char *)name;
    }
    return name[0] ? -1 : 0;
}

static const asn_INTEGER_enum_map_t *
INTEGER_map_enum2value(const asn_INTEGER_specifics_t *specs, const char *lstart,
                       const char *lstop) {
    const asn_INTEGER_enum_map_t *el_found;
    int count = specs ? specs->map_count : 0;
    struct e2v_key key;
    const char *lp;

    if(!count) return NULL;

    /* Guaranteed: assert(lstart < lstop); */
    /* Figure out the tag name */
    for(lstart++, lp = lstart; lp < lstop; lp++) {
        switch(*lp) {
        case 9: case 10: case 11: case 12: case 13: case 32: /* WSP */
        case 0x2f: /* '/' */ case 0x3e: /* '>' */
            break;
        default:
            continue;
        }
        break;
    }
    if(lp == lstop) return NULL;  /* No tag found */
    lstop = lp;

    key.start = lstart;
    key.stop = lstop;
    key.vemap = specs->value2enum;
    key.evmap = specs->enum2value;
    el_found = (asn_INTEGER_enum_map_t *)bsearch(&key,
        specs->value2enum, count, sizeof(specs->value2enum[0]),
        INTEGER__compar_enum2value);
    if(el_found) {
        /* Remap enum2value into value2enum */
        el_found = key.vemap + key.evmap[el_found - key.vemap];
    }
    return el_found;
}

static int
INTEGER_st_prealloc(INTEGER_t *st, int min_size) {
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
 * Decode the chunk of XML text encoding INTEGER.
 */
static enum xer_pbd_rval
INTEGER__xer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    const asn_INTEGER_specifics_t *specs =
        (const asn_INTEGER_specifics_t *)td->specifics;
    INTEGER_t *st = (INTEGER_t *)sptr;
    intmax_t dec_value;
    intmax_t hex_value = 0;
    const char *lp;
    const char *lstart = (const char *)chunk_buf;
    const char *lstop = lstart + chunk_size;
    enum {
        ST_LEADSPACE,
        ST_SKIPSPHEX,
        ST_WAITDIGITS,
        ST_DIGITS,
        ST_DIGITS_TRAILSPACE,
        ST_HEXDIGIT1,
        ST_HEXDIGIT2,
        ST_HEXDIGITS_TRAILSPACE,
        ST_HEXCOLON,
        ST_END_ENUM,
        ST_UNEXPECTED
    } state = ST_LEADSPACE;
    const char *dec_value_start = 0; /* INVARIANT: always !0 in ST_DIGITS */
    const char *dec_value_end = 0;

    if(chunk_size)
        ASN_DEBUG("INTEGER body %ld 0x%2x..0x%2x",
                  (long)chunk_size, *lstart, lstop[-1]);

    if(INTEGER_st_prealloc(st, (chunk_size/3) + 1))
        return XPBD_SYSTEM_FAILURE;

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
            case ST_HEXDIGITS_TRAILSPACE:
            case ST_SKIPSPHEX:
                continue;
            case ST_DIGITS:
                dec_value_end = lp;
                state = ST_DIGITS_TRAILSPACE;
                continue;
            case ST_HEXCOLON:
                state = ST_HEXDIGITS_TRAILSPACE;
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
        case 0x2b:  /* '+' */
            if(state == ST_LEADSPACE) {
                dec_value = 0;
                dec_value_start = lp;
                state = ST_WAITDIGITS;
                continue;
            }
            break;
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
            switch(state) {
            case ST_DIGITS: continue;
            case ST_SKIPSPHEX:  /* Fall through */
            case ST_HEXDIGIT1:
                hex_value = (lv - 0x30) << 4;
                state = ST_HEXDIGIT2;
                continue;
            case ST_HEXDIGIT2:
                hex_value += (lv - 0x30);
                state = ST_HEXCOLON;
                st->buf[st->size++] = (uint8_t)hex_value;
                continue;
            case ST_HEXCOLON:
                return XPBD_BROKEN_ENCODING;
            case ST_LEADSPACE:
                dec_value = 0;
                dec_value_start = lp;
                /* FALL THROUGH */
            case ST_WAITDIGITS:
                state = ST_DIGITS;
                continue;
            default:
                break;
            }
            break;
        case 0x3c:  /* '<', start of XML encoded enumeration */
            if(state == ST_LEADSPACE) {
                const asn_INTEGER_enum_map_t *el;
                el = INTEGER_map_enum2value(
                    (const asn_INTEGER_specifics_t *)
                    td->specifics, lstart, lstop);
                if(el) {
                    ASN_DEBUG("Found \"%s\" => %ld",
                              el->enum_name, el->nat_value);
                    dec_value = el->nat_value;
                    state = ST_END_ENUM;
                    lp = lstop - 1;
                    continue;
                }
                ASN_DEBUG("Unknown identifier for INTEGER");
            }
            return XPBD_BROKEN_ENCODING;
        case 0x3a:  /* ':' */
            if(state == ST_HEXCOLON) {
                /* This colon is expected */
                state = ST_HEXDIGIT1;
                continue;
            } else if(state == ST_DIGITS) {
                /* The colon here means that we have
                 * decoded the first two hexadecimal
                 * places as a decimal value.
                 * Switch decoding mode. */
                ASN_DEBUG("INTEGER re-evaluate as hex form");
                state = ST_SKIPSPHEX;
                dec_value_start = 0;
                lp = lstart - 1;
                continue;
            } else {
                ASN_DEBUG("state %d at %ld", state, (long)(lp - lstart));
                break;
            }
        /* [A-Fa-f] */
        case 0x41:case 0x42:case 0x43:case 0x44:case 0x45:case 0x46:
        case 0x61:case 0x62:case 0x63:case 0x64:case 0x65:case 0x66:
            switch(state) {
            case ST_SKIPSPHEX:
            case ST_LEADSPACE: /* Fall through */
            case ST_HEXDIGIT1:
                hex_value = lv - ((lv < 0x61) ? 0x41 : 0x61);
                hex_value += 10;
                hex_value <<= 4;
                state = ST_HEXDIGIT2;
                continue;
            case ST_HEXDIGIT2:
                hex_value += lv - ((lv < 0x61) ? 0x41 : 0x61);
                hex_value += 10;
                st->buf[st->size++] = (uint8_t)hex_value;
                state = ST_HEXCOLON;
                continue;
            case ST_DIGITS:
                ASN_DEBUG("INTEGER re-evaluate as hex form");
                state = ST_SKIPSPHEX;
                dec_value_start = 0;
                lp = lstart - 1;
                continue;
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
    case ST_END_ENUM:
        /* Got a complete and valid enumeration encoded as a tag. */
        break;
    case ST_DIGITS:
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
                 * We model INTEGER on long for XER,
                 * to avoid rewriting all the tests at once.
                 */
                ASN_DEBUG("INTEGER exceeds long range");
            }
            /* Fall through */
        case ASN_STRTOX_ERROR_RANGE:
            ASN_DEBUG("INTEGER decode %s hit range limit", td->name);
            return XPBD_DECODER_LIMIT;
        case ASN_STRTOX_ERROR_INVAL:
        case ASN_STRTOX_EXPECT_MORE:
        case ASN_STRTOX_EXTRA_DATA:
            return XPBD_BROKEN_ENCODING;
        }
        break;
    case ST_HEXCOLON:
    case ST_HEXDIGITS_TRAILSPACE:
        st->buf[st->size] = 0;  /* Just in case termination */
        return XPBD_BODY_CONSUMED;
    case ST_HEXDIGIT1:
    case ST_HEXDIGIT2:
    case ST_SKIPSPHEX:
        return XPBD_BROKEN_ENCODING;
    case ST_LEADSPACE:
        /* Content not found */
        return XPBD_NOT_BODY_IGNORE;
    case ST_WAITDIGITS:
    case ST_UNEXPECTED:
        ASN_DEBUG("INTEGER: No useful digits (state %d)", state);
        return XPBD_BROKEN_ENCODING;  /* No digits */
    }

    /*
     * Convert the result of parsing of enumeration or a straight
     * decimal value into a BER representation.
     */
    if(asn_imax2INTEGER(st, dec_value)) {
                ASN_DEBUG("INTEGER decode %s conversion failed", td->name);
        return XPBD_SYSTEM_FAILURE;
        }

    return XPBD_BODY_CONSUMED;
}

asn_dec_rval_t
INTEGER_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **sptr,
                   const char *opt_mname, const void *buf_ptr, size_t size) {
    return xer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(INTEGER_t), opt_mname,
        buf_ptr, size, INTEGER__xer_body_decode);
}

asn_enc_rval_t
INTEGER_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum xer_encoder_flags_e flags,
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
