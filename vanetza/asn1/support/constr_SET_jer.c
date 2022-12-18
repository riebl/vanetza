/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SET.h"

asn_enc_rval_t
SET_encode_jer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
               enum jer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    asn_enc_rval_t er;
    int xcan = 0;
    const asn_TYPE_tag2member_t *t2m = specs->tag2el_cxer;
    size_t t2m_count = specs->tag2el_cxer_count;
    size_t edx;

    if(!sptr)
        ASN__ENCODE_FAILED;

    assert(t2m_count == td->elements_count);

    er.encoded = 0;

    for(edx = 0; edx < t2m_count; edx++) {
        asn_enc_rval_t tmper;
        asn_TYPE_member_t *elm;
        const void *memb_ptr;
        const char *mname;
        size_t mlen;

        elm = &td->elements[t2m[edx].el_no];
        mname = elm->name;
        mlen = strlen(elm->name);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                if(elm->optional)
                    continue;
                /* Mandatory element missing */
                ASN__ENCODE_FAILED;
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        if(!xcan)
            ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK3("\"", 1, mname, mlen, "\"", 1);

        /* Print the member itself */
        tmper = elm->type->op->jer_encoder(elm->type, memb_ptr,
                                           ilevel + 1, flags,
                                           cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        //        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
