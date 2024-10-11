/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_application.h"
#include "asn_internal.h"
#include "BIT_STRING.h"
#include "INTEGER.h"

asn_enc_rval_t
BIT_STRING_encode_jer(const asn_TYPE_descriptor_t *td,
                      const asn_jer_constraints_t *constraints,
                      const void *sptr, int ilevel,
                      enum jer_encoder_flags_e flags,
                      asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
    const char * const h2c = "0123456789ABCDEF";
    char scratch[16 * 3 + 4];
    char *p = scratch;
    const BIT_STRING_t *st = (const BIT_STRING_t *)sptr;
    const asn_jer_constraints_t* cts = constraints ?
        constraints : td->encoding_constraints.jer_constraints;
    uint8_t *buf;
    uint8_t *end;

    (void)ilevel;
    (void)flags;

    int jmin = flags & JER_F_MINIFIED;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = 0;

    buf = st->buf;
    end = buf + st->size - 1;  /* Last byte is special */

    /*
     * Hex dump
     */
    if(cts->size != -1) { /* Fixed size */
        *p++ = '"';
        for(int i = 0; buf < end; buf++, i++) {
            if(!(i % 16) && (i || st->size > 16)) {
                ASN__CALLBACK(scratch, p-scratch);
                p = scratch;
            }
            *p++ = h2c[*buf >> 4];
            *p++ = h2c[*buf & 0x0F];
        }

        ASN__CALLBACK(scratch, p - scratch);
        p = scratch;

        if(buf == end) {
            int ubits = st->bits_unused;
            uint8_t v = *buf & (0xff << ubits);
            *p++ = h2c[v >> 4];
            *p++ = h2c[v & 0x0F];
            ASN__CALLBACK(scratch, p - scratch);
            p = scratch;
        }
        *p++ = '"';
        ASN__CALLBACK(scratch, p - scratch);
    } else { /* Variable size */
        ASN__CALLBACK("{", 1);
        if(!jmin) {
            ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK("\"value\": ", 9);
        } else {
            ASN__CALLBACK("\"value\":", 8);
        }
        *p++ = '"';
        for(int i = 0; buf < end; buf++, i++) {
            if(!(i % 16) && (i || st->size > 16)) {
                ASN__CALLBACK(scratch, p-scratch);
                p = scratch;
            }
            *p++ = h2c[*buf >> 4];
            *p++ = h2c[*buf & 0x0F];
        }

        ASN__CALLBACK(scratch, p - scratch);
        p = scratch;

        if(buf == end) {
            int ubits = st->bits_unused;
            uint8_t v = *buf & (0xff << ubits);
            *p++ = h2c[v >> 4];
            *p++ = h2c[v & 0x0F];
            ASN__CALLBACK(scratch, p - scratch);
            p = scratch;
        }
        *p++ = '"';
        ASN__CALLBACK(scratch, p - scratch);

        ASN__CALLBACK(",", 1);
        if (!jmin) {
            ASN__TEXT_INDENT(1, ilevel + 1);
        }

        if(!jmin) {
            ASN__CALLBACK("\"length\": ", 10);
        } else {
            ASN__CALLBACK("\"length\":", 9);
        }
        int wr = snprintf(scratch, sizeof(scratch), "%lu",
                st->size * 8 - (st->bits_unused));
        if(wr < 0 || wr >= sizeof(scratch)) {
            ASN__ENCODE_FAILED;
        }
        ASN__CALLBACK(scratch, wr);
        if (!jmin) {
            ASN__TEXT_INDENT(1, ilevel);
        }
        ASN__CALLBACK("}", 1);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

#define SKIPCHAR(_c)                 \
    do {                             \
        int found = 0;               \
        for (; p < pend; ++p) {      \
            if (*p == _c) {          \
                found = 1; ++p;      \
                break;               \
            }                        \
        }                            \
        if(!found) RETURN(RC_WMORE); \
    } while(0)

asn_dec_rval_t
BIT_STRING_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                            const asn_TYPE_descriptor_t *td,
                            const asn_jer_constraints_t *constraints,
                            void **sptr,
                            const void *buf_ptr, size_t size) {
    BIT_STRING_t *st = (BIT_STRING_t *)*sptr;
    const asn_jer_constraints_t *cts = constraints ?
        constraints : td->encoding_constraints.jer_constraints;
    asn_dec_rval_t rval;  /* Return value from the decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from buf_ptr */

    /*
     * Create the string if does not exist.
     */
    if(!st) {
        st = (BIT_STRING_t *)(*sptr = CALLOC(1, sizeof(*st)));
        if(!st) ASN__DECODE_FAILED;
    }

    const char *p = (const char*)buf_ptr;
    const char *pend = p + size;

    if(cts->size == -1) {
        SKIPCHAR('{');
        SKIPCHAR('"');
        if(pend-p < 5) RETURN(RC_WMORE);
        if(0 != memcmp(p, "value", 5)) RETURN(RC_FAIL);
        p += 5;
        SKIPCHAR('"');
        SKIPCHAR(':');
    }

    /* bitstring value */
    SKIPCHAR('"');

    /* calculate size */
    const char* p0 = p;
    SKIPCHAR('"');
    const char* p1 = p - 1;
    p = p0;

    void *nptr = REALLOC(st->buf, (p1-p0 + 1) / 2 + 1);
    if(!nptr) RETURN(RC_FAIL);
    st->buf = (uint8_t *)nptr;
    uint8_t *buf = st->buf;
    unsigned int clv = 0;
    int half = 0;

    for(; p < p1; p++) {
        int ch = *(const unsigned char *)p;
        switch(ch) {
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
        case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
            clv = (clv << 4) + (ch - 0x30);
            break;
        case 0x41: case 0x42: case 0x43:  /* ABC */
        case 0x44: case 0x45: case 0x46:  /* DEF */
            clv = (clv << 4) + (ch - 0x41 + 10);
            break;
        case 0x61: case 0x62: case 0x63:  /* abc */
        case 0x64: case 0x65: case 0x66:  /* def */
            clv = (clv << 4) + (ch - 0x61 + 10);
            break;
        default:
            *buf = 0;  /* JIC */
            RETURN(RC_FAIL);
        }
        if(half++) {
            half = 0;
            *buf++ = clv;
        }
    }

    /*
     * Check partial decoding.
     */
    if(half) {
        RETURN(RC_FAIL);
    }

    st->size = buf - st->buf;  /* Adjust the buffer size */
    st->buf[st->size] = 0;  /* Courtesy termination */

    SKIPCHAR('"');

    if(cts->size == -1) {
        SKIPCHAR(',');
        SKIPCHAR('"');
        if(pend-p < 6) RETURN(RC_WMORE);
        if(0 != memcmp(p, "length", 6)) RETURN(RC_FAIL);
        p += 6;
        SKIPCHAR('"');
        SKIPCHAR(':');
        p0 = p;
        /* Skip whitespace, numbers, for length calc for INTEGER dec
         * Stop on first non-whitespace/non-number */
        int numbered = 0;
        for (; p < pend; ++p) {
            switch (*p) {
                case 0x09: case 0x0a: case 0x0c: case 0x0d:
                case 0x20:
                    if(!numbered) continue;
                    else break;
                    /* Ignore whitespace */
                case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:  /*01234*/
                case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:  /*56789*/
                case 0x2d:  /*-*/
                    numbered = 1;
                    continue;
            }
            if(numbered) break;
        }
        if(!numbered) RETURN(RC_FAIL);

        unsigned long length;

        INTEGER_t integer = { 0 };
        void *integer_ptr = (void *)&integer;
        memset(&integer, 0, sizeof(integer));

        asn_dec_rval_t dec =
            INTEGER_decode_jer(NULL, &asn_DEF_INTEGER, NULL, &integer_ptr, p0, p-p0);
        if(dec.code == RC_OK) {
            if(asn_INTEGER2ulong(&integer, (unsigned long *)&length)) {
                RETURN(RC_FAIL);
            }
        } else {
            RETURN(RC_FAIL);
        }
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_INTEGER, &integer);

        if(dec.code != RC_OK) RETURN(RC_FAIL);
        st->bits_unused = (st->size * 8) - length;

        SKIPCHAR('}');
    } else {
        if(st->size * 8 < cts->size) {
            RETURN(RC_FAIL);
        }
        st->bits_unused = (st->size * 8) - cts->size;
    }

    consumed_myself = (const char *)p - (const char *)buf_ptr;
    RETURN(RC_OK);
}

