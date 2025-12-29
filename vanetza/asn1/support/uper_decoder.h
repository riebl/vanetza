/*-
 * Copyright (c) 2005-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_UPER_DECODER_H_
#define	_UPER_DECODER_H_

#include "asn_application.h"
#include "uper_support.h"

#ifdef __cplusplus
extern "C" {
#endif

struct asn_TYPE_descriptor_s;	/* Forward declaration */

/* Flags used by the uper_decode() functions */
enum uper_decoder_flags_e {
	/* Mode of decoding */
	UPER_F_BASIC      = 0x00,	/* BASIC-UPER (default, lenient) */
	UPER_F_CANONICAL  = 0x01	/* CANONICAL-UPER (strict rules) */
};

/*
 * Unaligned PER decoder of a "complete encoding" as per X.691 (08/2015) #11.1.
 * On success, this call always returns (.consumed >= 1), as per #11.1.3.
 */
asn_dec_rval_t uper_decode_complete(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of data buffer */
);

/*
 * Unaligned PER decoder of any ASN.1 type. May be invoked by the application.
 * WARNING: This call returns the number of BITS read from the stream. Beware.
 */
asn_dec_rval_t uper_decode(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size,        /* Size of the input data buffer, in bytes */
    int skip_bits,      /* Number of unused leading bits, 0..7 */
    int unused_bits     /* Number of unused tailing bits, 0..7 */
);

/*
 * Canonical Unaligned PER decoder variants that enforce strict X.691 rules.
 */
asn_dec_rval_t uper_decode_complete_canonical(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of data buffer */
);

asn_dec_rval_t uper_decode_canonical(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size,        /* Size of the input data buffer, in bytes */
    int skip_bits,      /* Number of unused leading bits, 0..7 */
    int unused_bits     /* Number of unused tailing bits, 0..7 */
);

/*
 * Lenient Canonical UPER decoder variants for interoperability.
 * These perform canonical validation but allow non-canonical encodings
 * from other implementations to decode successfully with warnings.
 */
asn_dec_rval_t uper_decode_complete_canonical_lenient(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size         /* Size of data buffer */
);

asn_dec_rval_t uper_decode_canonical_lenient(
    const struct asn_codec_ctx_s *opt_codec_ctx,
    const struct asn_TYPE_descriptor_s *type_descriptor, /* Type to decode */
    void **struct_ptr,  /* Pointer to a target structure's pointer */
    const void *buffer, /* Data to be decoded */
    size_t size,        /* Size of the input data buffer, in bytes */
    int skip_bits,      /* Number of unused leading bits, 0..7 */
    int unused_bits     /* Number of unused tailing bits, 0..7 */
);

#ifdef __cplusplus
}
#endif

#endif	/* _UPER_DECODER_H_ */
