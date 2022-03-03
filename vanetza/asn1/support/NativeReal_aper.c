/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"
#include "OCTET_STRING.h"

asn_dec_rval_t
NativeReal_decode_aper(const asn_codec_ctx_t *opt_codec_ctx,
                       const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints,
                       void **dbl_ptr, asn_per_data_t *pd) {
    double *Dbl = (double *)*dbl_ptr;
    asn_dec_rval_t rval;
    REAL_t tmp;
    void *ptmp = &tmp;
    int ret;

    (void)constraints;

    /*
     * If the structure is not there, allocate it.
     */
    if(Dbl == NULL) {
        *dbl_ptr = CALLOC(1, sizeof(*Dbl));
        Dbl = (double *)*dbl_ptr;
        if(Dbl == NULL)
            ASN__DECODE_FAILED;
    }

    memset(&tmp, 0, sizeof(tmp));
    rval = OCTET_STRING_decode_aper(opt_codec_ctx, td, NULL,
            &ptmp, pd);
    if(rval.code != RC_OK) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
        return rval;
    }

    ret = asn_REAL2double(&tmp, Dbl);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);
    if(ret) ASN__DECODE_FAILED;

    return rval;
}

asn_enc_rval_t
NativeReal_encode_aper(const asn_TYPE_descriptor_t *td,
                       const asn_per_constraints_t *constraints,
                       const void *sptr, asn_per_outp_t *po) {
    double Dbl = *(const double *)sptr;
    asn_enc_rval_t erval = {0,0,0};
    REAL_t tmp;

    (void)constraints;

    /* Prepare a temporary clean structure */
    memset(&tmp, 0, sizeof(tmp));

    if(asn_double2REAL(&tmp, Dbl))
        ASN__ENCODE_FAILED;

    /* Encode a DER REAL */
    erval = OCTET_STRING_encode_aper(td, NULL, &tmp, po);
    if(erval.encoded == -1)
        erval.structure_ptr = sptr;

    /* Free possibly allocated members of the temporary structure */
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_REAL, &tmp);

    return erval;
}
