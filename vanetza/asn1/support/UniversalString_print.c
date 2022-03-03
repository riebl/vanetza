/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "UniversalString.h"

int
UniversalString_print(const asn_TYPE_descriptor_t *td, const void *sptr,
                      int ilevel, asn_app_consume_bytes_f *cb, void *app_key) {
    const UniversalString_t *st = (const UniversalString_t *)sptr;

    (void)td;  /* Unused argument */
    (void)ilevel;  /* Unused argument */

    if(!st || !st->buf) return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;

    if(UniversalString__dump(st, cb, app_key) < 0)
        return -1;

    return 0;
}
