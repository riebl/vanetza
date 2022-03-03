/*-
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>.
 * 	All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "RELATIVE-OID.h"
#include <limits.h>	/* for CHAR_BIT */
#include <errno.h>

/*
 * RELATIVE-OID basic type description.
 */
static const ber_tlv_tag_t asn_DEF_RELATIVE_OID_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (13 << 2))
};
asn_TYPE_operation_t asn_OP_RELATIVE_OID = {
    ASN__PRIMITIVE_TYPE_free,
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    RELATIVE_OID_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    OCTET_STRING_compare,  /* Implemented in terms of opaque comparison */
#if !defined(ASN_DISABLE_BER_SUPPORT)
    ber_decode_primitive,
    der_encode_primitive,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    RELATIVE_OID_decode_xer,
    RELATIVE_OID_encode_xer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    RELATIVE_OID_decode_oer,
    RELATIVE_OID_encode_oer,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT)
    OCTET_STRING_decode_uper,
    OCTET_STRING_encode_uper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) */
#if !defined(ASN_DISABLE_APER_SUPPORT)
    OCTET_STRING_decode_aper,
    OCTET_STRING_encode_aper,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_RFILL_SUPPORT)
    RELATIVE_OID_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_RELATIVE_OID = {
    "RELATIVE-OID",
    "RELATIVE_OID",
    &asn_OP_RELATIVE_OID,
    asn_DEF_RELATIVE_OID_tags,
    sizeof(asn_DEF_RELATIVE_OID_tags)
        / sizeof(asn_DEF_RELATIVE_OID_tags[0]),
    asn_DEF_RELATIVE_OID_tags,  /* Same as above */
    sizeof(asn_DEF_RELATIVE_OID_tags)
        / sizeof(asn_DEF_RELATIVE_OID_tags[0]),
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
        asn_generic_no_constraint
    },
    0, 0,  /* No members */
    0  /* No specifics */
};

ssize_t
RELATIVE_OID__dump_body(const RELATIVE_OID_t *st, asn_app_consume_bytes_f *cb, void *app_key) {
    char scratch[32];
    size_t produced = 0;
    size_t off = 0;

    for(;;) {
        asn_oid_arc_t arc;
        ssize_t rd = OBJECT_IDENTIFIER_get_single_arc(st->buf + off,
                                                      st->size - off, &arc);
        if(rd < 0) {
            return -1;
        } else if(rd == 0) {
            /* No more arcs. */
            break;
        } else {
            int ret = snprintf(scratch, sizeof(scratch), "%s%" PRIu32,
                               off ? "." : "", arc);
            if(ret >= (ssize_t)sizeof(scratch)) {
                return -1;
            }
            produced += ret;
            off += rd;
            assert(off <= st->size);
            if(cb(scratch, ret, app_key) < 0) return -1;
        }
    }

    if(off != st->size) {
        ASN_DEBUG("Could not scan to the end of Object Identifier");
        return -1;
    }

	return produced;
}

ssize_t
RELATIVE_OID_get_arcs(const RELATIVE_OID_t *st, asn_oid_arc_t *arcs,
                      size_t arcs_count) {
    size_t num_arcs = 0;
    size_t off;

    if(!st || !st->buf) {
        errno = EINVAL;
        return -1;
    }

    for(off = 0;;) {
        asn_oid_arc_t arc;
        ssize_t rd = OBJECT_IDENTIFIER_get_single_arc(st->buf + off,
                                                      st->size - off, &arc);
        if(rd < 0) {
            return -1;
        } else if(rd == 0) {
            /* No more arcs. */
            break;
        } else {
            off += rd;
            if(num_arcs < arcs_count) {
                arcs[num_arcs] = arc;
            }
            num_arcs++;
        }
    }

    if(off != st->size) {
        return -1;
    }

	return num_arcs;
}

int
RELATIVE_OID_set_arcs(RELATIVE_OID_t *st, const asn_oid_arc_t *arcs,
                      size_t arcs_count) {
    uint8_t *buf;
	uint8_t *bp;
    size_t size;
	size_t i;

	if(!st || !arcs) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Roughly estimate the maximum size necessary to encode these arcs.
	 */
    size = ((sizeof(asn_oid_arc_t) * CHAR_BIT + 6) / 7) * arcs_count;
    bp = buf = (uint8_t *)MALLOC(size + 1);
	if(!buf) {
		/* ENOMEM */
		return -1;
	}

	/*
	 * Encode the arcs.
	 */
    for(i = 0; i < arcs_count; i++) {
        ssize_t wrote = OBJECT_IDENTIFIER_set_single_arc(bp, size, arcs[i]);
        if(wrote <= 0) {
            FREEMEM(buf);
            return -1;
        }
        assert((size_t)wrote <= size);
        bp += wrote;
        size -= wrote;
    }

	/*
	 * Replace buffer.
	 */
	st->size = bp - buf;
	bp = st->buf;
	st->buf = buf;
	st->buf[st->size] = '\0';
	if(bp) FREEMEM(bp);

	return 0;
}
