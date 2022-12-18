/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "UniversalString.h"
#include "UTF8String.h"

asn_enc_rval_t
UniversalString_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                           int ilevel, enum jer_encoder_flags_e flags,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    const UniversalString_t *st = (const UniversalString_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;
    (void)flags;

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = UniversalString__dump(st, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
