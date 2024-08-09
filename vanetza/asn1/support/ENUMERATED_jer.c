/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "ENUMERATED.h"
#include "INTEGER.h"

struct e2v_key {
    const char *start;
    const char *stop;
    const asn_INTEGER_enum_map_t *vemap;
    const unsigned int *evmap;
};
static int
ENUMERATED__jer_compar_enum2value(const void *kp, const void *am) {
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
ENUMERATED_jer_map_enum2value(const asn_INTEGER_specifics_t *specs, const char *lstart,
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
        case 0x22: /* '"' */
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
        ENUMERATED__jer_compar_enum2value);
    if(el_found) {
        /* Remap enum2value into value2enum */
        el_found = key.vemap + key.evmap[el_found - key.vemap];
    }
    return el_found;
}

static enum jer_pbd_rval
ENUMERATED__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                         const void *chunk_buf, size_t chunk_size) {
    INTEGER_t *st = (INTEGER_t *)sptr;
    intmax_t dec_value;
    const char *lp;
    const char *lstart = (const char *)chunk_buf;
    const char *lstop = lstart + chunk_size;
    int decoded = 0;

    for (lp = lstart; lp < lstop; ++lp) {
        if (*lp == 0x22 /* '"' */) { 
            const asn_INTEGER_enum_map_t *el;
            el = ENUMERATED_jer_map_enum2value(
                    (const asn_INTEGER_specifics_t *)
                    td->specifics, lstart, lstop);
            if(el) {
                ASN_DEBUG("Found \"%s\" => %ld",
                        el->enum_name, el->nat_value);
                dec_value = el->nat_value;
                decoded = 1;
                lp = lstop - 1;
                continue;
            }
            ASN_DEBUG("Unknown identifier for ENUMERATED");
        } else {
            continue;
        }
    }

    if (!decoded) {
        return JPBD_BROKEN_ENCODING;;
    }

    /*
     * Convert the result of parsing of enumeration into a BER representation.
     */
    if(asn_imax2INTEGER(st, dec_value)) {
        ASN_DEBUG("ENUMERATED decode %s conversion failed", td->name);
        return JPBD_SYSTEM_FAILURE;
    }

    return JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
ENUMERATED_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                   const asn_TYPE_descriptor_t *td, void **sptr,
                   const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td,
        sptr, sizeof(INTEGER_t),
        buf_ptr, size, ENUMERATED__jer_body_decode);
}
