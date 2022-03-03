/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"
#include "OCTET_STRING.h"

/*
 * Decode REAL type using PER.
 */
asn_dec_rval_t
NativeReal_decode_uper(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints, void **sptr,
                       asn_per_data_t *pd) {
    asn_dec_rval_t rval;
    double d;
    REAL_t tmp;
    void *ptmp = &tmp;
    int ret;

    (void)constraints;

    memset(&tmp, 0, sizeof(tmp));
    rval = OCTET_STRING_decode_uper(opt_codec_ctx, &asn_DEF_REAL,
                                    NULL, &ptmp, pd);
    if(rval.code != RC_OK) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
        return rval;
    }

    ret = asn_REAL2double(&tmp, &d);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
    if(ret) ASN__DECODE_FAILED;

    if(NativeReal__set(td, sptr, d) < 0 )
        ASN__DECODE_FAILED;

    return rval;
}

/*
 * Encode the NativeReal using the OCTET STRING PER encoder.
 */
asn_enc_rval_t
NativeReal_encode_uper(const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints,
                       const void *sptr, asn_per_outp_t *po) {
    double d = NativeReal__get_double(td, sptr);
    asn_enc_rval_t erval = {0,0,0};
    REAL_t tmp;

    (void)constraints;

    /* Prepare a temporary clean structure */
    memset(&tmp, 0, sizeof(tmp));

    if(asn_double2REAL(&tmp, d))
        ASN__ENCODE_FAILED;

    /* Encode a DER REAL */
    erval = OCTET_STRING_encode_uper(&asn_DEF_REAL, NULL, &tmp, po);
    if(erval.encoded == -1)
        erval.structure_ptr = sptr;

    /* Free possibly allocated members of the temporary structure */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);

    return erval;
}
