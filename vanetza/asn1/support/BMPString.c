/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "BMPString.h"

/*
 * BMPString basic type description.
 */
static const ber_tlv_tag_t asn_DEF_BMPString_tags[] = {
    (ASN_TAG_CLASS_UNIVERSAL | (30 << 2)),  /* [UNIVERSAL 30] IMPLICIT ...*/
    (ASN_TAG_CLASS_UNIVERSAL | (4 << 2))    /* ... OCTET STRING */
};
asn_OCTET_STRING_specifics_t asn_SPC_BMPString_specs = {
    sizeof(BMPString_t),
    offsetof(BMPString_t, _asn_ctx),
    ASN_OSUBV_U16  /* 16-bits character */
};
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_DEF_BMPString_per_constraints = {
    { APC_CONSTRAINED, 16, 16, 0, 65535 },
    { APC_SEMI_CONSTRAINED, -1, -1, 0, 0 },
    0, 0
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_operation_t asn_OP_BMPString = {
    OCTET_STRING_free,  /* Implemented in terms of OCTET STRING */
#if !defined(ASN_DISABLE_PRINT_SUPPORT)
    BMPString_print,
#else
    0,
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) */
    OCTET_STRING_compare,
#if !defined(ASN_DISABLE_BER_SUPPORT)
    OCTET_STRING_decode_ber,
    OCTET_STRING_encode_der,
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_BER_SUPPORT) */
#if !defined(ASN_DISABLE_XER_SUPPORT)
    BMPString_decode_xer,  /* Convert from UTF-8 */
    BMPString_encode_xer,  /* Convert to UTF-8 */
#else
    0,
    0,
#endif  /* !defined(ASN_DISABLE_XER_SUPPORT) */
#if !defined(ASN_DISABLE_OER_SUPPORT)
    OCTET_STRING_decode_oer,
    OCTET_STRING_encode_oer,
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
    OCTET_STRING_random_fill,
#else
    0,
#endif  /* !defined(ASN_DISABLE_RFILL_SUPPORT) */
    0  /* Use generic outmost tag fetcher */
};
asn_TYPE_descriptor_t asn_DEF_BMPString = {
    "BMPString",
    "BMPString",
    &asn_OP_BMPString,
    asn_DEF_BMPString_tags,
    sizeof(asn_DEF_BMPString_tags)
      / sizeof(asn_DEF_BMPString_tags[0]) - 1,
    asn_DEF_BMPString_tags,
    sizeof(asn_DEF_BMPString_tags)
      / sizeof(asn_DEF_BMPString_tags[0]),
    {
#if !defined(ASN_DISABLE_OER_SUPPORT)
        0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
        &asn_DEF_BMPString_per_constraints,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
        BMPString_constraint
    },
    0, 0,  /* No members */
    &asn_SPC_BMPString_specs
};

int
BMPString_constraint(const asn_TYPE_descriptor_t *td, const void *sptr,
                     asn_app_constraint_failed_f *ctfailcb, void *app_key) {
    const BMPString_t *st = (const BMPString_t *)sptr;

    if(st && st->buf) {
        if(st->size & 1) {
            ASN__CTFAIL(app_key, td, sptr,
                        "%s: invalid size %" ASN_PRI_SIZE " not divisible by 2 (%s:%d)",
                        td->name, st->size, __FILE__, __LINE__);
            return -1;
        }
    } else {
        ASN__CTFAIL(app_key, td, sptr, "%s: value not given (%s:%d)", td->name,
                    __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

#if !defined(ASN_DISABLE_PRINT_SUPPORT) || !defined(ASN_DISABLE_XER_SUPPORT)
/*
 * BMPString specific contents printer.
 */
ssize_t
BMPString__dump(const BMPString_t *st,
		asn_app_consume_bytes_f *cb, void *app_key) {
	char scratch[128];			/* Scratchpad buffer */
	char *p = scratch;
	ssize_t wrote = 0;
	uint8_t *ch;
	uint8_t *end;

	ch = st->buf;
	end = (st->buf + st->size);
	for(end--; ch < end; ch += 2) {
		uint16_t wc = (ch[0] << 8) | ch[1];	/* 2 bytes */
		if(sizeof(scratch) - (p - scratch) < 3) {
			wrote += p - scratch;
			if(cb(scratch, p - scratch, app_key) < 0)
				return -1;
			p = scratch;
		}
		if(wc < 0x80) {
			*p++ = (char)wc;
		} else if(wc < 0x800) {
			*p++ = 0xc0 | ((wc >> 6));
			*p++ = 0x80 | ((wc & 0x3f));
		} else {
			*p++ = 0xe0 | ((wc >> 12));
			*p++ = 0x80 | ((wc >> 6) & 0x3f);
			*p++ = 0x80 | ((wc & 0x3f));
		}
	}

	wrote += p - scratch;
	if(cb(scratch, p - scratch, app_key) < 0)
		return -1;

	return wrote;
}
#endif  /* !defined(ASN_DISABLE_PRINT_SUPPORT) || !defined(ASN_DISABLE_XER_SUPPORT) */
