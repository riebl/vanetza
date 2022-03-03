/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SET.h"

/*
 * Return a standardized complex structure.
 */
#undef RETURN
#define RETURN(_code)                     \
    do {                                  \
        rval.code = _code;                \
        rval.consumed = consumed_myself;  \
        return rval;                      \
    } while(0)

#undef XER_ADVANCE
#define XER_ADVANCE(num_bytes)                    \
    do {                                          \
        size_t num = num_bytes;                   \
        buf_ptr = ((const char *)buf_ptr) + num;  \
        size -= num;                              \
        consumed_myself += num;                   \
    } while(0)

/*
 * Decode the XER (XML) data.
 */
asn_dec_rval_t
SET_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
               const asn_TYPE_descriptor_t *td, void **struct_ptr,
               const char *opt_mname, const void *buf_ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elements = td->elements;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval;          /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    size_t edx;                   /* Element index */

    /*
     * Create the target structure if it is not present already.
     */
    if(st == 0) {
        st = *struct_ptr = CALLOC(1, specs->struct_size);
        if(st == 0) RETURN(RC_FAIL);
    }

    /*
     * Restore parsing context.
     */
    ctx = (asn_struct_ctx_t *)((char *)st + specs->ctx_offset);

    /*
     * Phases of XER/XML processing:
     * Phase 0: Check that the opening tag matches our expectations.
     * Phase 1: Processing body and reacting on closing tag.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 3;) {
        pxer_chunk_type_e ch_type;  /* XER chunk type */
        ssize_t ch_size;            /* Chunk size */
        xer_check_tag_e tcv;        /* Tag check value */
        const asn_TYPE_member_t *elm;

        /*
         * Go inside the inner member of a set.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval;
            void *memb_ptr_dontuse;  /* Pointer to the member */
            void **memb_ptr2;        /* Pointer to that pointer */

            if(ASN_SET_ISPRESENT2((char *)st + specs->pres_offset,
                                  edx)) {
                ASN_DEBUG("SET %s: Duplicate element %s (%" ASN_PRI_SSIZE ")",
                          td->name, elements[edx].name, edx);
                RETURN(RC_FAIL);
            }

            elm = &elements[edx];

            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elm->memb_offset);
            } else {
                memb_ptr_dontuse = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr_dontuse;  /* Only use of memb_ptr_dontuse */
            }

            /* Invoke the inner type decoder, m.b. multiple times */
            tmprval = elm->type->op->xer_decoder(opt_codec_ctx,
                                                 elm->type, memb_ptr2, elm->name,
                                                 buf_ptr, size);
            XER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, edx);
            ASN_DEBUG("XER/SET phase => %d", ctx->phase);
            /* Fall through */
        }

        /*
         * Get the next part of the XML stream.
         */
        ch_size = xer_next_token(&ctx->context,
                                 buf_ptr, size, &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PXER_WMORE:
                RETURN(RC_WMORE);
            case PXER_COMMENT:  /* Got XML comment */
            case PXER_TEXT:  /* Ignore free-standing text */
                XER_ADVANCE(ch_size);  /* Skip silently */
                continue;
            case PXER_TAG:
                break;  /* Check the rest down there */
            }
        }

        tcv = xer_check_tag(buf_ptr, ch_size, xml_tag);
        ASN_DEBUG("XER/SET: tcv = %d, ph=%d", tcv, ctx->phase);

        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(xer_skip_unknown(tcv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 1:
                ctx->phase = 1;
                /* Fall through */
            case 0:
                XER_ADVANCE(ch_size);
                continue;
            case 2:
                ctx->phase = 1;
                break;
            }
        }

        switch(tcv) {
        case XCT_CLOSING:
            if(ctx->phase == 0) break;
            ctx->phase = 0;
            /* Fall through */
        case XCT_BOTH:
            if(ctx->phase == 0) {
                if(_SET_is_populated(td, st)) {
                    XER_ADVANCE(ch_size);
                    ctx->phase = 4;  /* Phase out */
                    RETURN(RC_OK);
                } else {
                    ASN_DEBUG("Premature end of XER SET");
                    RETURN(RC_FAIL);
                }
            }
            /* Fall through */
        case XCT_OPENING:
            if(ctx->phase == 0) {
                XER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }
            /* Fall through */
        case XCT_UNKNOWN_OP:
        case XCT_UNKNOWN_BO:

            ASN_DEBUG("XER/SET: tcv=%d, ph=%d", tcv, ctx->phase);
            if(ctx->phase != 1)
                break;  /* Really unexpected */

            /*
             * Search which member corresponds to this tag.
             */
            for(edx = 0; edx < td->elements_count; edx++) {
                switch(xer_check_tag(buf_ptr, ch_size,
                    elements[edx].name)) {
                case XCT_BOTH:
                case XCT_OPENING:
                    /*
                     * Process this member.
                     */
                    ctx->step = edx;
                    ctx->phase = 2;
                    break;
                case XCT_UNKNOWN_OP:
                case XCT_UNKNOWN_BO:
                    continue;
                default:
                    edx = td->elements_count;
                    break;  /* Phase out */
                }
                break;
            }
            if(edx != td->elements_count)
                continue;

            /* It is expected extension */
            if(specs->extensible) {
                ASN_DEBUG("Got anticipated extension");
                /*
                 * Check for (XCT_BOTH or XCT_UNKNOWN_BO)
                 * By using a mask. Only record a pure
                 * <opening> tags.
                 */
                if(tcv & XCT_CLOSING) {
                    /* Found </extension> without body */
                } else {
                    ctx->left = 1;
                    ctx->phase = 3;  /* Skip ...'s */
                }
                XER_ADVANCE(ch_size);
                continue;
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected XML tag in SET, expected \"%s\"",
                  xml_tag);
        break;
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

asn_enc_rval_t
SET_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
               enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
               void *app_key) {
    const asn_SET_specifics_t *specs = (const asn_SET_specifics_t *)td->specifics;
    asn_enc_rval_t er;
    int xcan = (flags & XER_F_CANONICAL);
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
        ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

        /* Print the member itself */
        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr,
                                           ilevel + 1, flags,
                                           cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
