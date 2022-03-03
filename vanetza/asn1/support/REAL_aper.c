/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "REAL.h"
#include "OCTET_STRING.h"

asn_dec_rval_t
REAL_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                 const asn_TYPE_descriptor_t *td,
                 const asn_per_constraints_t *constraints,
                 void **sptr, asn_per_data_t *pd) {
    (void)constraints;  /* No PER visible constraints */
    return OCTET_STRING_decode_aper(opt_codec_ctx, td, 0, sptr, pd);
}

asn_enc_rval_t
REAL_encode_aper(const asn_TYPE_descriptor_t *td,
                 const asn_per_constraints_t *constraints,
                 const void *sptr, asn_per_outp_t *po) {
    (void)constraints;  /* No PER visible constraints */
    return OCTET_STRING_encode_aper(td, 0, sptr, po);
}
