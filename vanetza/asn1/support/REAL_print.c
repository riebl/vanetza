/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "REAL.h"

int
REAL_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
           asn_app_consume_bytes_f *cb, void *app_key) {
    const REAL_t *st = (const REAL_t *)sptr;
    ssize_t ret;
    double d;

    (void)td;  /* Unused argument */
    (void)ilevel;  /* Unused argument */

    if(!st || !st->buf)
        ret = cb("<absent>", 8, app_key);
    else if(asn_REAL2double(st, &d))
        ret = cb("<error>", 7, app_key);
    else
        ret = REAL__dump(d, 0, cb, app_key);

    return (ret < 0) ? -1 : 0;
}
