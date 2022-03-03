/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "GeneralizedTime.h"
#include <errno.h>

#ifdef __CYGWIN__
#include "/usr/include/time.h"
#else
#include <time.h>
#endif  /* __CYGWIN__ */

asn_enc_rval_t
GeneralizedTime_encode_der(const asn_TYPE_descriptor_t *td, const void *sptr,
                           int tag_mode, ber_tlv_tag_t tag,
                           asn_app_consume_bytes_f *cb, void *app_key) {
    GeneralizedTime_t *st;
    asn_enc_rval_t erval = {0,0,0};
    int fv, fd;  /* seconds fraction value and number of digits */
    struct tm tm;
    time_t tloc;

    /*
     * Encode as a canonical DER.
     */
    errno = EPERM;
    tloc = asn_GT2time_frac((const GeneralizedTime_t *)sptr, &fv, &fd, &tm,
                            1);  /* Recognize time */
    if(tloc == -1 && errno != EPERM) {
        /* Failed to recognize time. Fail completely. */
        ASN__ENCODE_FAILED;
    }

    st = asn_time2GT_frac(0, &tm, fv, fd, 1);  /* Save time canonically */
    if(!st) ASN__ENCODE_FAILED;                /* Memory allocation failure. */

    erval = OCTET_STRING_encode_der(td, st, tag_mode, tag, cb, app_key);

    ASN_STRUCT_FREE(*td, st);

    return erval;
}
