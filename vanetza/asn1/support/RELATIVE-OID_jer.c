/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "RELATIVE-OID.h"

asn_enc_rval_t
RELATIVE_OID_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr,
                        int ilevel, enum jer_encoder_flags_e flags,
                        asn_app_consume_bytes_f *cb, void *app_key) {
    const RELATIVE_OID_t *st = (const RELATIVE_OID_t *)sptr;
    asn_enc_rval_t er = {0,0,0};

    (void)ilevel;  /* Unused argument */
    (void)flags;  /* Unused argument */

    if(!st || !st->buf)
        ASN__ENCODE_FAILED;

    er.encoded = RELATIVE_OID__dump_body(st, cb, app_key);
    if(er.encoded < 0) ASN__ENCODE_FAILED;

    ASN__ENCODED_OK(er);
}
