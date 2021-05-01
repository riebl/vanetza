/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"

/*
 * Swap bytes from/to network, if local is little-endian.
 * Unused endianness sections are likely removed at compile phase.
 */
static void
NativeReal__network_swap(size_t float_size, const void *srcp, uint8_t *dst) {
    const uint8_t *src = srcp;
    double test = -0.0;
    int float_big_endian = *(const char *)&test != 0;
    /* In lieu of static_assert(sizeof(double) == 8) */
    static const char sizeof_double_is_8_a[sizeof(double)-7] CC_NOTUSED;
    static const char sizeof_double_is_8_b[9-sizeof(double)] CC_NOTUSED;
    /* In lieu of static_assert(sizeof(sizeof) == 4) */
    static const char sizeof_float_is_4_a[sizeof(float)-3] CC_NOTUSED;
    static const char sizeof_float_is_4_b[5-sizeof(float)] CC_NOTUSED;

    switch(float_size) {
    case sizeof(double):
        assert(sizeof(double) == 8);
        if(float_big_endian) {
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = src[3];
            dst[4] = src[4];
            dst[5] = src[5];
            dst[6] = src[6];
            dst[7] = src[7];
        } else {
            dst[0] = src[7];
            dst[1] = src[6];
            dst[2] = src[5];
            dst[3] = src[4];
            dst[4] = src[3];
            dst[5] = src[2];
            dst[6] = src[1];
            dst[7] = src[0];
        }
        return;
    case sizeof(float):
        assert(sizeof(float) == 4);
        if(float_big_endian) {
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = src[3];
        } else {
            dst[0] = src[3];
            dst[1] = src[2];
            dst[2] = src[1];
            dst[3] = src[0];
        }
        return;
    }
}

/*
 * Encode as Canonical OER.
 */
asn_enc_rval_t
NativeReal_encode_oer(const asn_TYPE_descriptor_t *td,
                      const asn_oer_constraints_t *constraints,
                      const void *sptr, asn_app_consume_bytes_f *cb,
                      void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};

    if(!constraints) constraints = td->encoding_constraints.oer_constraints;
    if(constraints && constraints->value.width != 0) {
        /* X.696 IEEE 754 binary32 and binary64 encoding */
        uint8_t scratch[sizeof(double)];
        const asn_NativeReal_specifics_t *specs =
            (const asn_NativeReal_specifics_t *)td->specifics;
        size_t wire_size = constraints->value.width;

        if(specs ? (wire_size == specs->float_size)
                 : (wire_size == sizeof(double))) {
            /*
             * Our representation matches the wire, modulo endianness.
             * That was the whole point of compact encoding!
             */
        } else {
            assert((wire_size == sizeof(double))
                   || (specs && specs->float_size == wire_size));
            ASN__ENCODE_FAILED;
        }

        /*
         * The X.696 standard doesn't specify endianness, neither is IEEE 754.
         * So we assume the network format is big endian.
         */
        NativeReal__network_swap(wire_size, sptr, scratch);
        if(cb(scratch, wire_size, app_key) < 0) {
            ASN__ENCODE_FAILED;
        } else {
            er.encoded = wire_size;
            ASN__ENCODED_OK(er);
        }
    } else {
        double d = NativeReal__get_double(td, sptr);
        ssize_t len_len;
        REAL_t tmp;

        /* Prepare a temporary clean structure */
        memset(&tmp, 0, sizeof(tmp));

        if(asn_double2REAL(&tmp, d)) {
            ASN__ENCODE_FAILED;
        }

        /* Encode a fake REAL */
        len_len = oer_serialize_length(tmp.size, cb, app_key);
        if(len_len < 0 || cb(tmp.buf, tmp.size, app_key) < 0) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
            ASN__ENCODE_FAILED;
        } else {
            er.encoded = len_len + tmp.size;
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
            ASN__ENCODED_OK(er);
        }
    }
}

asn_dec_rval_t
NativeReal_decode_oer(const asn_codec_ctx_t *opt_codec_ctx,
                      const asn_TYPE_descriptor_t *td,
                      const asn_oer_constraints_t *constraints, void **sptr,
                      const void *ptr, size_t size) {
    asn_dec_rval_t ok = {RC_OK, 0};
    double d;
    ssize_t len_len;
    size_t real_body_len;

    (void)opt_codec_ctx;

    if(!constraints) constraints = td->encoding_constraints.oer_constraints;
    if(constraints && constraints->value.width != 0) {
        /* X.696 IEEE 754 binary32 and binary64 encoding */
        uint8_t scratch[sizeof(double)];
        size_t wire_size = constraints->value.width;

        if(size < wire_size)
            ASN__DECODE_STARVED;

        /*
         * The X.696 standard doesn't specify endianness, neither is IEEE 754.
         * So we assume the network format is big endian.
         */
        NativeReal__network_swap(wire_size, ptr, scratch);


        switch(wire_size) {
            case sizeof(double):
                {
                    double tmp;
                    memcpy(&tmp, scratch, sizeof(double));
                    if(NativeReal__set(td, sptr, tmp) < 0)
                        ASN__DECODE_FAILED;
                }
                break;
            case sizeof(float):
                {
                    float tmp;
                    memcpy(&tmp, scratch, sizeof(float));
                    if(NativeReal__set(td, sptr, tmp) < 0)
                        ASN__DECODE_FAILED;
                }
                break;
        default:
            ASN__DECODE_FAILED;
        }

        ok.consumed = wire_size;
        return ok;
    }

    len_len = oer_fetch_length(ptr, size, &real_body_len);
    if(len_len < 0) ASN__DECODE_FAILED;
    if(len_len == 0) ASN__DECODE_STARVED;

    ptr = (const char *)ptr + len_len;
    size -= len_len;

    if(real_body_len > size) ASN__DECODE_STARVED;

    {
        uint8_t scratch[24]; /* Longer than %.16f in decimal */
        REAL_t tmp;
        int ret;

        if(real_body_len < sizeof(scratch)) {
            tmp.buf = scratch;
            tmp.size = real_body_len;
        } else {
            /* This rarely happens: impractically long value */
            tmp.buf = CALLOC(1, real_body_len + 1);
            tmp.size = real_body_len;
            if(!tmp.buf) {
                ASN__DECODE_FAILED;
            }
        }

        memcpy(tmp.buf, ptr, real_body_len);
        tmp.buf[real_body_len] = '\0';

        ret = asn_REAL2double(&tmp, &d);
        if(tmp.buf != scratch) FREEMEM(tmp.buf);
        if(ret) {
            ASN_DEBUG("REAL decoded in %" ASN_PRI_SIZE " bytes, but can't convert t double",
                      real_body_len);
            ASN__DECODE_FAILED;
        }
    }

    if(NativeReal__set(td, sptr, d) < 0)
        ASN__DECODE_FAILED;

    ok.consumed = len_len + real_body_len;
    return ok;
}
