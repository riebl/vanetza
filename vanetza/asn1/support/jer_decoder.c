/*
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_application.h"
#include "asn_internal.h"
#include "jer_support.h"		/* JER/JSON parsing support */


/*
 * Decode the jer encoding of a given type.
 */
asn_dec_rval_t
jer_decode(const asn_codec_ctx_t *opt_codec_ctx,
           const asn_TYPE_descriptor_t *td, void **struct_ptr,
           const void *buffer, size_t size) {
    asn_codec_ctx_t s_codec_ctx;

	/*
	 * Stack checker requires that the codec context
	 * must be allocated on the stack.
	 */
	if(opt_codec_ctx) {
		if(opt_codec_ctx->max_stack_size) {
			s_codec_ctx = *opt_codec_ctx;
			opt_codec_ctx = &s_codec_ctx;
		}
	} else {
		/* If context is not given, be security-conscious anyway */
		memset(&s_codec_ctx, 0, sizeof(s_codec_ctx));
		s_codec_ctx.max_stack_size = ASN__DEFAULT_STACK_MAX;
		opt_codec_ctx = &s_codec_ctx;
	}

	/*
	 * Invoke type-specific decoder.
	 */
    return td->op->jer_decoder(opt_codec_ctx, td, 0, struct_ptr, buffer, size);
}



struct jer__cb_arg {
	pjson_chunk_type_e	chunk_type;
	size_t			chunk_size;
	const void		*chunk_buf;
	int callback_not_invoked;
};

static int
jer__token_cb(pjson_chunk_type_e type, const void *_chunk_data, size_t _chunk_size, void *key) {
	struct jer__cb_arg *arg = (struct jer__cb_arg *)key;
	arg->chunk_type = type;
	arg->chunk_size = _chunk_size;
	arg->chunk_buf = _chunk_data;
	arg->callback_not_invoked = 0;
	return -1;	/* Terminate the JSON parsing */
}

/*
 * Fetch the next token from the JER/JSON stream.
 */
ssize_t
jer_next_token(int *stateContext, const void *buffer, size_t size, pjer_chunk_type_e *ch_type) {
	struct jer__cb_arg arg;
	int new_stateContext = *stateContext;
	ssize_t ret;

	arg.callback_not_invoked = 1;
	ret = pjson_parse(&new_stateContext, buffer, size, jer__token_cb, &arg);
	if(ret < 0) return -1;
	if(arg.callback_not_invoked) {
		assert(ret == 0);	/* No data was consumed */
        *ch_type = PJER_WMORE;
		return 0;		/* Try again with more data */
	} else {
		assert(arg.chunk_size);
		assert(arg.chunk_buf == buffer);
	}

	/*
	 * Translate the JSON chunk types into more convenient ones.
	 */
	switch(arg.chunk_type) {
	case PJSON_TEXT:
		*ch_type = PJER_TEXT;
		break;
	case PJSON_KEY:
		*ch_type = PJER_WMORE;
        break;
    case PJSON_DLM:
        *ch_type = PJER_DLM;
        break;
	case PJSON_KEY_END:
		*ch_type = PJER_KEY;
        break;
	case PJSON_VALUE_END:
		*ch_type = PJER_VALUE;
        break;
    default:
		return 0;	/* Want more */
	}

	*stateContext = new_stateContext;
	return arg.chunk_size;
}

#define LCBRAC  0x7b    /* '{' */
#define RCBRAC  0x7d    /* '}' */
#define	CQUOTE	0x22	/* '"' */
#define	CCOMMA	0x2c	/* ',' */
#define	LSBRAC	0x5b	/* '[' */
#define	RSBRAC	0x5d	/* ']' */

jer_check_sym_e
jer_check_sym(const void *buf_ptr, int size, const char *need_key) {
	const char *buf = (const char *)buf_ptr;
	const char *end;

    if(!need_key) { /* expected data end */
        switch(buf[size-1]) {
        case LCBRAC:
            return JCK_OSTART;
        case RCBRAC:
            return JCK_OEND;
        case LSBRAC:
            return JCK_ASTART;
        case RSBRAC:
            return JCK_AEND;
        case CCOMMA:
            return JCK_COMMA;
        default:
            return JCK_UNKNOWN;
        }
    } 

	if(size < 2 || 
            (buf[0] != CQUOTE || buf[size-1] != CQUOTE)) {
		if(size >= 2)
			ASN_DEBUG("Broken JSON key: \"%c...%c\"",
			buf[0], buf[size - 1]);
		return JCK_BROKEN;
	}

    buf++;		/* advance past first quote */
    size -= 2;	/* strip quotes */

	/*
	 * Determine the key name.
	 */
	for(end = buf + size; buf < end; buf++, need_key++) {
		int b = *buf, n = *need_key;
		if(b != n) {
			if(n == 0) {
				switch(b) {
				case 0x09: case 0x0a: case 0x0c: case 0x0d:
				case 0x20:
					/* "abc def": accept whitespace */
					return JCK_KEY;
				}
			}
			return JCK_UNKNOWN;
		}
		if(b == 0)
			return JCK_BROKEN;	/* Embedded 0 in buf?! */
	}
	if(*need_key)
		return JCK_UNKNOWN;

	return JCK_KEY;
}


#undef	ADVANCE
#define	ADVANCE(num_bytes)	do {				\
		size_t num = (num_bytes);			\
		buf_ptr = ((const char *)buf_ptr) + num;	\
		size -= num;					\
		consumed_myself += num;				\
	} while(0)

#undef	RETURN
#define	RETURN(_code)	do {					\
		rval.code = _code;				\
		rval.consumed = consumed_myself;		\
		if(rval.code != RC_OK)				\
			ASN_DEBUG("Failed with %d", rval.code);	\
		return rval;					\
	} while(0)

#define	JER_GOT_BODY(chunk_buf, chunk_size, size)	do {	\
		ssize_t converted_size = body_receiver		\
			(struct_key, chunk_buf, chunk_size,	\
				(size_t)chunk_size <= size);	\
		if(converted_size == -1) RETURN(RC_FAIL);	\
		if(converted_size == 0				\
			&& size == (size_t)chunk_size)		\
			RETURN(RC_WMORE);			\
		chunk_size = converted_size;			\
	} while(0)
#define	JER_GOT_EMPTY()	do {					\
	if(body_receiver(struct_key, 0, 0, size > 0) == -1)	\
			RETURN(RC_FAIL);			\
	} while(0)

/*
 * Generalized function for decoding the primitive values.
 */
asn_dec_rval_t
jer_decode_general(const asn_codec_ctx_t *opt_codec_ctx,
	asn_struct_ctx_t *ctx,	/* Type decoder context */
	void *struct_key,
	const void *buf_ptr, size_t size,
	int (*opt_unexpected_key_decoder)
		(void *struct_key, const void *chunk_buf, size_t chunk_size),
	ssize_t (*body_receiver)
		(void *struct_key, const void *chunk_buf, size_t chunk_size,
			int have_more)
	) {

	asn_dec_rval_t rval;
	ssize_t consumed_myself = 0;

	(void)opt_codec_ctx;
    (void)opt_unexpected_key_decoder;

	/*
	 * Phases of jer/JSON processing:
	 * Phase 0: Check that the opening key matches our expectations.
	 * Phase 1: Processing body and reacting on closing token.
	 */
	if(ctx->phase > 1) RETURN(RC_FAIL);
	for(;;) {
		pjer_chunk_type_e ch_type;	/* jer chunk type */
		ssize_t ch_size;		/* Chunk size */

		/*
		 * Get the next part of the JSON stream.
		 */
		ch_size = jer_next_token(&ctx->context, buf_ptr, size,
			&ch_type);
		if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
			switch(ch_type) {
			case PJER_WMORE:
                RETURN(RC_WMORE);
			case PJER_TEXT:
                ADVANCE(ch_size);
				continue;
			case PJER_VALUE:
				JER_GOT_BODY(buf_ptr, ch_size, size);
				ADVANCE(ch_size);
                ADVANCE(jer_whitespace_span(buf_ptr, size)); /* skip whitespace */
                ch_size = 1;
            case PJER_KEY:
            case PJER_DLM:
                break;	/* Check the rest down there */
			}
		}

        ctx->phase = 2;	/* Phase out */
        RETURN(RC_OK);

		break;	/* Dark and mysterious things have just happened */
	}

	RETURN(RC_FAIL);
}


size_t
jer_whitespace_span(const void *chunk_buf, size_t chunk_size) {
	const char *p = (const char *)chunk_buf;
	const char *pend = (p == NULL)? NULL : p + chunk_size;

	for(; p < pend; p++) {
		switch(*p) {
		/* X.693, #8.1.4
		 * HORISONTAL TAB (9)
		 * LINE FEED (10) 
		 * CARRIAGE RETURN (13) 
		 * SPACE (32)
		 */
		case 0x09: case 0x0a: case 0x0d: case 0x20:
			continue;
		default:
			break;
		}
		break;
	}
	return (p - (const char *)chunk_buf);
}

/*
 * This is a vastly simplified, non-validating JSON tree skipper. [TODO]
 */
int
jer_skip_unknown(jer_check_sym_e scv, ber_tlv_len_t *depth) {
	assert(*depth > 0);
	switch(scv) {
	case JCK_KEY:
		++(*depth);
		return 0;
	case JCK_COMMA:
	case JCK_OEND:
	case JCK_UNKNOWN:
		if(--(*depth) == 0)
			return (scv == JCK_OEND) ? 2 : 1;
		return 0;
	default:
		return -1;
	}
}
