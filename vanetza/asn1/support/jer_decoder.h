/*-
 * Copyright (c) 2004-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_JER_DECODER_H_
#define	_JER_DECODER_H_

#include "asn_application.h"
#include "jer_support.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/*
 * The JER decoder of any ASN.1 type. May be invoked by the application.
 * Decodes CANONICAL-JER and BASIC-JER.
 */
asn_dec_rval_t jer_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of data buffer */
);

/*
 * Type of the type-specific JER decoder function.
 */
typedef asn_dec_rval_t(jer_type_decoder_f)(
    const asn_codec_ctx_t *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_jer_constraints_t *constraints,
    void **struct_ptr,
    const void *buf_ptr, size_t size);

/*******************************
 * INTERNALLY USEFUL FUNCTIONS *
 *******************************/

/*
 * Generalized function for decoding the primitive values.
 * Used by more specialized functions, such as OCTET_STRING_decode_jer_utf8
 * and others. This function should not be used by applications, as its API
 * is subject to changes.
 */
asn_dec_rval_t jer_decode_general(
    const asn_codec_ctx_t *opt_codec_ctx,
    asn_struct_ctx_t *ctx, /* Type decoder context */
    void *struct_key,      /* Treated as opaque pointer */
    const void *buf_ptr, size_t size,
    int (*opt_unexpected_tag_decoder)(void *struct_key, const void *chunk_buf,
                                      size_t chunk_size),
    ssize_t (*body_receiver)(void *struct_key, const void *chunk_buf,
                             size_t chunk_size, int have_more));


/*
 * Fetch the next JER (JSON) token from the stream.
 * The function returns the number of bytes occupied by the chunk type,
 * returned in the _ch_type. The _ch_type is only set (and valid) when
 * the return value is >= 0.
 */
typedef enum pjer_chunk_type {
	PJER_WMORE,     /* Chunk type is not clear, more data expected. */
	PJER_TEXT,	    /* General data */
	PJER_KEY,	    /* Complete JSON key */
    PJER_VALUE,     /* Complete JSON value */
	PJER_DLM	    /* JSON delimiter */
  } pjer_chunk_type_e;
ssize_t jer_next_token(int *stateContext,
	const void *buffer, size_t size, pjer_chunk_type_e *_ch_type);

/*
 * This function checks the buffer for the current token or 
 * against the key name expected to occur.
 */
typedef enum jer_check_sym {
	JCK_BROKEN,	  /* Something is broken */
	JCK_UNKNOWN,  /* Key or delimiter is unknown */	
	JCK_KEY,	  /* Key is OK */
	JCK_COMMA,    /* Delimiter is ',' */
	JCK_OSTART,	  /* Delimiter is '{' */
	JCK_OEND,     /* Delimiter is '}' */
	JCK_ASTART,	  /* Delimiter is '[' */
	JCK_AEND      /* Delimiter is ']' */
} jer_check_sym_e;
jer_check_sym_e jer_check_sym(const void *buf_ptr, int size,
		const char *need_key);

/*
 * Get the number of bytes consisting entirely of JER whitespace characters.
 * RETURN VALUES:
 * >=0:	Number of whitespace characters in the string.
 */
size_t jer_whitespace_span(const void *chunk_buf, size_t chunk_size);

/*
 * Skip the series of anticipated extensions.
 */
int jer_skip_unknown(jer_check_sym_e scv, ber_tlv_len_t *depth);

#ifdef __cplusplus
}
#endif

#endif	/* _JER_DECODER_H_ */
