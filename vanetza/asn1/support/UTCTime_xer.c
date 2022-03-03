/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "UTCTime.h"
#include <errno.h>

#ifdef __CYGWIN__
#include "/usr/include/time.h"
#else
#include <time.h>
#endif  /* __CYGWIN__ */

#if !defined(ASN___INTERNAL_TEST_MODE)

asn_enc_rval_t
UTCTime_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                   int ilevel, enum xer_encoder_flags_e flags,
                   asn_app_consume_bytes_f *cb, void *app_key) {
    if(flags & XER_F_CANONICAL) {
        asn_enc_rval_t rv;
        UTCTime_t *ut;
        struct tm tm;

        errno = EPERM;
        if(asn_UT2time((const UTCTime_t *)sptr, &tm, 1) == -1
        && errno != EPERM)
            ASN__ENCODE_FAILED;

        /* Fractions are not allowed in UTCTime */
        ut = asn_time2UT(0, &tm, 1);
        if(!ut) ASN__ENCODE_FAILED;

        rv = OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
                                          cb, app_key);
        OCTET_STRING_free(&asn_DEF_UTCTime, ut, 0);
        return rv;
    } else {
        return OCTET_STRING_encode_xer_utf8(td, sptr, ilevel, flags,
                                            cb, app_key);
    }
}

#endif  /* !defined(ASN___INTERNAL_TEST_MODE) */
