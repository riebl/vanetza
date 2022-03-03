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

int
GeneralizedTime_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
    const GeneralizedTime_t *st = (const GeneralizedTime_t *)sptr;

    (void)td;  /* Unused argument */
    (void)ilevel;  /* Unused argument */

    if(st && st->buf) {
        char buf[32];
        struct tm tm;
        int ret;

        errno = EPERM;
        if(asn_GT2time(st, &tm, 1) == -1 && errno != EPERM)
            return (cb("<bad-value>", 11, app_key) < 0) ? -1 : 0;

        ret = snprintf(buf, sizeof(buf),
            "%04d-%02d-%02d %02d:%02d:%02d (GMT)",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
        assert(ret > 0 && ret < (int)sizeof(buf));
        return (cb(buf, ret, app_key) < 0) ? -1 : 0;
    } else {
        return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
    }
}
