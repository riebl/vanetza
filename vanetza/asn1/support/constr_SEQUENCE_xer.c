/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SEQUENCE.h"
#include "OPEN_TYPE.h"

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

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef XER_ADVANCE
#define XER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

/*
 * Decode the XER (XML) data.
 */
asn_dec_rval_t
SEQUENCE_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **struct_ptr,
                    const char *opt_mname, const void *ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SEQUENCE_specifics_t *specs
        = (const asn_SEQUENCE_specifics_t *)td->specifics;
    asn_TYPE_member_t *elements = td->elements;
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
        asn_TYPE_member_t *elm;

        /*
         * Go inside the inner member of a sequence.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval;
            void *memb_ptr_dontuse;  /* Pointer to the member */
            void **memb_ptr2;        /* Pointer to that pointer */

            elm = &td->elements[edx];

            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st + elm->memb_offset);
            } else {
                memb_ptr_dontuse = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr_dontuse;  /* Only use of memb_ptr_dontuse */
            }

            if(elm->flags & ATF_OPEN_TYPE) {
                tmprval = OPEN_TYPE_xer_get(opt_codec_ctx, td, st, elm, ptr, size);
            } else {
                /* Invoke the inner type decoder, m.b. multiple times */
                tmprval = elm->type->op->xer_decoder(opt_codec_ctx,
                                                     elm->type, memb_ptr2, elm->name,
                                                     ptr, size);
            }
            XER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ctx->step = ++edx;
            ASN_DEBUG("XER/SEQUENCE phase => %d, step => %d",
                ctx->phase, ctx->step);
            /* Fall through */
        }

        /*
         * Get the next part of the XML stream.
         */
        ch_size = xer_next_token(&ctx->context, ptr, size,
            &ch_type);
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

        tcv = xer_check_tag(ptr, ch_size, xml_tag);
        ASN_DEBUG("XER/SEQUENCE: tcv = %d, ph=%d [%s]",
                  tcv, ctx->phase, xml_tag);

        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(xer_skip_unknown(tcv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 0:
                XER_ADVANCE(ch_size);
                continue;
            case 1:
                XER_ADVANCE(ch_size);
                ctx->phase = 1;
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
                if(edx >= td->elements_count ||
                   /* Explicit OPTIONAL specs reaches the end */
                   (edx + elements[edx].optional == td->elements_count) ||
                   /* All extensions are optional */
                   IN_EXTENSION_GROUP(specs, edx)) {
                    XER_ADVANCE(ch_size);
                    ctx->phase = 4;  /* Phase out */
                    RETURN(RC_OK);
                } else {
                    ASN_DEBUG("Premature end of XER SEQUENCE");
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

            ASN_DEBUG("XER/SEQUENCE: tcv=%d, ph=%d, edx=%" ASN_PRI_SIZE "",
                      tcv, ctx->phase, edx);
            if(ctx->phase != 1) {
                break;  /* Really unexpected */
            }

            if(edx < td->elements_count) {
                /*
                 * Search which member corresponds to this tag.
                 */
                size_t n;
                size_t edx_end = edx + elements[edx].optional + 1;
                if(edx_end > td->elements_count)
                    edx_end = td->elements_count;
                for(n = edx; n < edx_end; n++) {
                    elm = &td->elements[n];
                    tcv = xer_check_tag(ptr, ch_size, elm->name);
                    switch(tcv) {
                    case XCT_BOTH:
                    case XCT_OPENING:
                        /*
                         * Process this member.
                         */
                        ctx->step = edx = n;
                        ctx->phase = 2;
                        break;
                    case XCT_UNKNOWN_OP:
                    case XCT_UNKNOWN_BO:
                        continue;
                    default:
                        n = edx_end;
                        break;  /* Phase out */
                    }
                    break;
                }
                if(n != edx_end)
                    continue;
            } else {
                ASN_DEBUG("Out of defined members: %" ASN_PRI_SIZE "/%u",
                          edx, td->elements_count);
            }

            /* It is expected extension */
            if(IN_EXTENSION_GROUP(specs,
                edx + (edx < td->elements_count
                    ? elements[edx].optional : 0))) {
                ASN_DEBUG("Got anticipated extension at %" ASN_PRI_SIZE "",
                          edx);
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

        ASN_DEBUG("Unexpected XML tag in SEQUENCE [%c%c%c%c%c%c]",
                  size>0?((const char *)ptr)[0]:'.',
                  size>1?((const char *)ptr)[1]:'.',
                  size>2?((const char *)ptr)[2]:'.',
                  size>3?((const char *)ptr)[3]:'.',
                  size>4?((const char *)ptr)[4]:'.',
                  size>5?((const char *)ptr)[5]:'.');
        break;
    }

    ctx->phase = 4;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

asn_enc_rval_t
SEQUENCE_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr,
                    int ilevel, enum xer_encoder_flags_e flags,
                    asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    int xcan = (flags & XER_F_CANONICAL);
    asn_TYPE_descriptor_t *tmp_def_val_td = 0;
    void *tmp_def_val = 0;
    size_t edx;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;

    for(edx = 0; edx < td->elements_count; edx++) {
        asn_enc_rval_t tmper = {0,0,0};
        asn_TYPE_member_t *elm = &td->elements[edx];
        const void *memb_ptr;
        const char *mname = elm->name;
        unsigned int mlen = strlen(mname);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) {
                assert(tmp_def_val == 0);
                if(elm->default_value_set) {
                    if(elm->default_value_set(&tmp_def_val)) {
                        ASN__ENCODE_FAILED;
                    } else {
                        memb_ptr = tmp_def_val;
                        tmp_def_val_td = elm->type;
                    }
                } else if(elm->optional) {
                    continue;
                } else {
                    /* Mandatory element is missing */
                    ASN__ENCODE_FAILED;
                }
            }
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        if(!xcan) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

        /* Print the member itself */
        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr, ilevel + 1,
                                           flags, cb, app_key);
        if(tmp_def_val) {
            ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
            tmp_def_val = 0;
        }
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!xcan) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    if(tmp_def_val) ASN_STRUCT_FREE(*tmp_def_val_td, tmp_def_val);
    ASN__ENCODE_FAILED;
}
