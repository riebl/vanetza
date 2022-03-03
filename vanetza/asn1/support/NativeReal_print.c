/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "NativeReal.h"
#include "REAL.h"

/*
 * REAL specific human-readable output.
 */
int
NativeReal_print(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                 asn_app_consume_bytes_f *cb, void *app_key) {
    (void)ilevel;  /* Unused argument */

    if(sptr) {
        double d = NativeReal__get_double(td, sptr);
        return (REAL__dump(d, 0, cb, app_key) < 0) ? -1 : 0;
    } else {
        return (cb("<absent>", 8, app_key) < 0) ? -1 : 0;
    }
}
