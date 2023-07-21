/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "asn_codecs_prim.h"
#include "BOOLEAN.h"
#include <errno.h>

asn_enc_rval_t
BOOLEAN_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum jer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    const BOOLEAN_t *st = (const BOOLEAN_t *)sptr;
    asn_enc_rval_t er = {0, 0, 0};

    (void)ilevel;
    (void)flags;

    if(!st) ASN__ENCODE_FAILED;

    if(*st) {
        ASN__CALLBACK("true", 4);
    } else {
        ASN__CALLBACK("false", 5);
    }

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
