/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include <errno.h>
#include "REAL.h"

struct specialRealValue_s specialRealValue_jer[] = {
#define SRV_SET(foo, val) { (char *)foo, sizeof(foo) - 1, val }
    SRV_SET("\"NaN\"", 0),
    SRV_SET("\"-INF\"", -1),
    SRV_SET("\"INF\"", 1),
    SRV_SET("\"-0\"", 2),
#undef SRV_SET
};

#if defined(__clang__)
/*
 * isnan() is defined using generic selections and won't compile in
 * strict C89 mode because of too fancy system's standard library.
 * However, prior to C11 the math had a perfectly working isnan()
 * in the math library.
 * Disable generic selection warning so we can test C89 mode with newer libc.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc11-extensions"
static int asn_isnan(double d) {
    return isnan(d);
}
static int asn_isfinite(double d) {
#ifdef isfinite
    return isfinite(d);  /* ISO C99 */
#else
    return finite(d);    /* Deprecated on Mac OS X 10.9 */
#endif
}
#pragma clang diagnostic pop
#else   /* !clang */
#define asn_isnan(v)    isnan(v)
#ifdef isfinite
#define asn_isfinite(d)   isfinite(d)  /* ISO C99 */
#else
#define asn_isfinite(d)   finite(d)    /* Deprecated on Mac OS X 10.9 */
#endif
#endif  /* clang */

static ssize_t
REAL__jer_dump(double d, int canonical, asn_app_consume_bytes_f *cb, void *app_key) {
	char local_buf[64];
	char *buf = local_buf;
	ssize_t buflen = sizeof(local_buf);
	ssize_t ret;

	/*
	 * Check whether it is a special value.
	 */
	/* fpclassify(3) is not portable yet */
	if(asn_isnan(d)) {
		buf = specialRealValue_jer[SRV__NOT_A_NUMBER].string;
		buflen = specialRealValue_jer[SRV__NOT_A_NUMBER].length;
		return (cb(buf, buflen, app_key) < 0) ? -1 : buflen;
	} else if(!asn_isfinite(d)) {
		if(copysign(1.0, d) < 0.0) {
			buf = specialRealValue_jer[SRV__MINUS_INFINITY].string;
			buflen = specialRealValue_jer[SRV__MINUS_INFINITY].length;
		} else {
			buf = specialRealValue_jer[SRV__PLUS_INFINITY].string;
			buflen = specialRealValue_jer[SRV__PLUS_INFINITY].length;
		}
		return (cb(buf, buflen, app_key) < 0) ? -1 : buflen;
	} else if(ilogb(d) <= -INT_MAX) {
		if(copysign(1.0, d) < 0.0) {
			buf = "\"-0\"";
			buflen = 4;
		} else {
			buf = "0";
			buflen = 1;
		}
		return (cb(buf, buflen, app_key) < 0) ? -1 : buflen;
	}

	/*
	 * Use the libc's double printing, hopefully they got it right.
	 */
	do {
        ret = snprintf(buf,
                       buflen,
                       canonical ? "%.17E" /* Precise */ : "%.15f" /* Pleasant*/,
                       d);
		if(ret < 0) {
			/* There are some old broken APIs. */
			buflen <<= 1;
			if(buflen > 4096) {
				/* Should be plenty. */
				if(buf != local_buf) FREEMEM(buf);
				return -1;
			}
		} else if(ret >= buflen) {
			buflen = ret + 1;
		} else {
			buflen = ret;
			break;
		}
		if(buf != local_buf) FREEMEM(buf);
		buf = (char *)MALLOC(buflen);
		if(!buf) return -1;
	} while(1);

	if(canonical) {
		/*
		 * Transform the "[-]d.dddE+-dd" output into "[-]d.dddE[-]d"
		 * Check that snprintf() constructed the output correctly.
		 */
		char *dot;
		char *end = buf + buflen;
		char *last_zero;
		char *first_zero_in_run;
        char *s;

        enum {
            LZSTATE_NOTHING,
            LZSTATE_ZEROES
        } lz_state = LZSTATE_NOTHING;

		dot = (buf[0] == 0x2d /* '-' */) ? (buf + 2) : (buf + 1);
		if(*dot >= 0x30) {
			if(buf != local_buf) FREEMEM(buf);
			errno = EINVAL;
			return -1;	/* Not a dot, really */
		}
		*dot = 0x2e;		/* Replace possible comma */

        for(first_zero_in_run = last_zero = s = dot + 2; s < end; s++) {
            switch(*s) {
            case 0x45: /* 'E' */
                if(lz_state == LZSTATE_ZEROES) last_zero = first_zero_in_run;
                break;
            case 0x30: /* '0' */
                if(lz_state == LZSTATE_NOTHING) first_zero_in_run = s;
                lz_state = LZSTATE_ZEROES;
                continue;
            default:
                lz_state = LZSTATE_NOTHING;
                continue;
            }
            break;
        }

		if(s == end) {
			if(buf != local_buf) FREEMEM(buf);
			errno = EINVAL;
			return -1;		/* No promised E */
		}

        assert(*s == 0x45);
        {
            int sign;
            char *E = s;
            char *expptr = ++E;

            s = expptr;

            if(*expptr == 0x2b /* '+' */) {
                /* Skip the "+" */
                buflen -= 1;
                sign = 0;
            } else {
                sign = 1;
                s++;
            }
            expptr++;
            if(expptr > end) {
                if(buf != local_buf) FREEMEM(buf);
                errno = EINVAL;
                return -1;
            }
            if(*expptr == 0x30) {
                buflen--;
                expptr++;
            }
            if(lz_state == LZSTATE_ZEROES) {
                *last_zero = 0x45;	/* E */
                buflen -= s - (last_zero + 1);
                s = last_zero + 1;
                if(sign) {
                    *s++ = 0x2d /* '-' */;
                    buflen++;
                }
            }
            for(; expptr <= end; s++, expptr++)
                *s = *expptr;
        }
	} else {
		/*
		 * Remove trailing zeros.
		 */
		char *end = buf + buflen;
		char *last_zero = end;
		int stoplooking = 0;
		char *z;
		for(z = end - 1; z > buf; z--) {
			switch(*z) {
			case 0x30:
				if(!stoplooking)
					last_zero = z;
				continue;
			case 0x31: case 0x32: case 0x33: case 0x34:
			case 0x35: case 0x36: case 0x37: case 0x38: case 0x39:
				stoplooking = 1;
				continue;
			default:	/* Catch dot and other separators */
				/*
				 * Replace possible comma (which may even
				 * be not a comma at all: locale-defined).
				 */
				*z = 0x2e;
				if(last_zero == z + 1) {	/* leave x.0 */
					last_zero++;
				}
				buflen = last_zero - buf;
				*last_zero = '\0';
				break;
			}
			break;
		}
	}

	ret = cb(buf, buflen, app_key);
	if(buf != local_buf) FREEMEM(buf);
	return (ret < 0) ? -1 : buflen;
}

asn_enc_rval_t
REAL_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                enum jer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
                void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    asn_enc_rval_t er = {0,0,0};
    double d;

    (void)ilevel;

    if(!st || !st->buf || asn_REAL2double(st, &d))
        ASN__ENCODE_FAILED;

    er.encoded = REAL__jer_dump(d, flags, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}

/*
 * Decode the chunk of JSON text encoding REAL.
 */
static enum jer_pbd_rval
REAL__jer_body_decode(const asn_TYPE_descriptor_t *td, void *sptr,
                      const void *chunk_buf, size_t chunk_size) {
    REAL_t *st = (REAL_t *)sptr;
    double value;
    const char *jerdata = (const char *)chunk_buf;
    char *endptr = 0;
    char *b;

    (void)td;

    if(!chunk_size) return JPBD_BROKEN_ENCODING;

    /*
     * Decode an JSONSpecialRealValue: "-INF", etc.
     */
    if(jerdata[0] == 0x22 /* '"' */) {
        size_t i;
        for(i = 0; i < sizeof(specialRealValue_jer) / sizeof(specialRealValue_jer[0]); i++) {
            struct specialRealValue_s *srv = &specialRealValue_jer[i];
            double dv;

            if(srv->length != chunk_size
            || memcmp(srv->string, chunk_buf, chunk_size))
                continue;

            /*
             * It could've been done using
             * (double)srv->dv / real_zero,
             * but it summons fp exception on some platforms.
             */
            switch(srv->dv) {
            case -1: dv = - INFINITY; break;
            case 0: dv = NAN;	break;
            case 1: dv = INFINITY;	break;
            case 2: dv = -0.0;	break;
            default: return JPBD_SYSTEM_FAILURE;
            }

            if(asn_double2REAL(st, dv))
                return JPBD_SYSTEM_FAILURE;

            return JPBD_BODY_CONSUMED;
        }
        ASN_DEBUG("Unknown JSONSpecialRealValue");
        return JPBD_BROKEN_ENCODING;
    }

    /*
     * Copy chunk into the nul-terminated string, and run strtod.
     */
    b = (char *)MALLOC(chunk_size + 1);
    if(!b) return JPBD_SYSTEM_FAILURE;
    memcpy(b, chunk_buf, chunk_size);
    b[chunk_size] = 0;	/* nul-terminate */

    value = strtod(b, &endptr);
    FREEMEM(b);
    if(endptr == b) return JPBD_BROKEN_ENCODING;

    if(asn_double2REAL(st, value))
        return JPBD_SYSTEM_FAILURE;

    return JPBD_BODY_CONSUMED;
}

asn_dec_rval_t
REAL_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                const asn_TYPE_descriptor_t *td, void **sptr,
                const void *buf_ptr, size_t size) {
    return jer_decode_primitive(opt_codec_ctx, td, sptr, sizeof(REAL_t),
                                buf_ptr, size, REAL__jer_body_decode);
}

