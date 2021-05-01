/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SEQUENCE_OF.h"
#include "asn_SEQUENCE_OF.h"

asn_enc_rval_t
SEQUENCE_OF_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                       int ilevel, enum xer_encoder_flags_e flags,
                       asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_sequence_ *list = _A_CSEQUENCE_FROM_VOID(sptr);
    const char *mname = specs->as_XMLValueList
                            ? 0
                            : ((*elm->name) ? elm->name : elm->type->xml_tag);
    size_t mlen = mname ? strlen(mname) : 0;
    int xcan = (flags & XER_F_CANONICAL);
    int i;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;

    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper = {0,0,0};
        void *memb_ptr = list->array[i];
        if(!memb_ptr) continue;

        if(mname) {
            if(!xcan) ASN__TEXT_INDENT(1, ilevel);
            ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);
        }

        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr, ilevel + 1,
                                           flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        if(tmper.encoded == 0 && specs->as_XMLValueList) {
            const char *name = elm->type->xml_tag;
            size_t len = strlen(name);
            if(!xcan) ASN__TEXT_INDENT(1, ilevel + 1);
            ASN__CALLBACK3("<", 1, name, len, "/>", 2);
        }

        if(mname) {
            ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
        }
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
