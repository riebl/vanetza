/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "ANY.h"

asn_enc_rval_t
ANY_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
               enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
    if(flags & XER_F_CANONICAL) {
        /*
         * Canonical XER-encoding of ANY type is not supported.
         */
        ASN__ENCODE_FAILED;
    }

    /* Dump as binary */
    return OCTET_STRING_encode_xer(td, sptr, ilevel, flags, cb, app_key);
}
