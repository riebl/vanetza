/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_CHOICE.h"

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
#define XER_ADVANCE(num_bytes)                                    \
    do {                                                          \
        size_t num = num_bytes;                                   \
        buf_ptr = (const void *)(((const char *)buf_ptr) + num);  \
        size -= num;                                              \
        consumed_myself += num;                                   \
    } while(0)

/*
 * Decode the XER (XML) data.
 */
asn_dec_rval_t
CHOICE_decode_xer(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td, void **struct_ptr,
                  const char *opt_mname, const void *buf_ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_CHOICE_specifics_t *specs = (const asn_CHOICE_specifics_t *)td->specifics;
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;

    /*
     * Parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval;          /* Return value of a decoder */
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
    if(ctx->phase == 0 && !*xml_tag)
        ctx->phase = 1;  /* Skip the outer tag checking phase */

    /*
     * Phases of XER/XML processing:
     * Phase 0: Check that the opening tag matches our expectations.
     * Phase 1: Processing body and reacting on closing tag.
     * Phase 2: Processing inner type.
     * Phase 3: Only waiting for closing tag.
     * Phase 4: Skipping unknown extensions.
     * Phase 5: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 4;) {
        pxer_chunk_type_e ch_type;  /* XER chunk type */
        ssize_t ch_size;            /* Chunk size */
        xer_check_tag_e tcv;        /* Tag check value */
        asn_TYPE_member_t *elm;

        /*
         * Go inside the member.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval;
            void *memb_ptr;    /* Pointer to the member */
            void **memb_ptr2;  /* Pointer to that pointer */
            unsigned old_present;

            elm = &td->elements[edx];

            if(elm->flags & ATF_POINTER) {
                /* Member is a pointer to another structure */
                memb_ptr2 = (void **)((char *)st
                    + elm->memb_offset);
            } else {
                memb_ptr = (char *)st + elm->memb_offset;
                memb_ptr2 = &memb_ptr;
            }

            /* Start/Continue decoding the inner member */
            tmprval = elm->type->op->xer_decoder(opt_codec_ctx,
                                                 elm->type, memb_ptr2,
                                                 elm->name,
                                                 buf_ptr, size);
            XER_ADVANCE(tmprval.consumed);
            ASN_DEBUG("XER/CHOICE: itdf: [%s] code=%d",
                      elm->type->name, tmprval.code);
            old_present = _fetch_present_idx(st,
                                             specs->pres_offset,
                                             specs->pres_size);
            assert(old_present == 0 || old_present == edx + 1);
            /* Record what we've got */
            _set_present_idx(st,
                             specs->pres_offset,
                             specs->pres_size, edx + 1);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 3;
            /* Fall through */
        }

        /* No need to wait for closing tag; special mode. */
        if(ctx->phase == 3 && !*xml_tag) {
            ctx->phase = 5;  /* Phase out */
            RETURN(RC_OK);
        }

        /*
         * Get the next part of the XML stream.
         */
        ch_size = xer_next_token(&ctx->context, buf_ptr, size, &ch_type);
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
        ASN_DEBUG("XER/CHOICE checked [%c%c%c%c] vs [%s], tcv=%d",
                  ch_size>0?((const uint8_t *)buf_ptr)[0]:'?',
                  ch_size>1?((const uint8_t *)buf_ptr)[1]:'?',
                  ch_size>2?((const uint8_t *)buf_ptr)[2]:'?',
                  ch_size>3?((const uint8_t *)buf_ptr)[3]:'?',
                  xml_tag, tcv);

        /* Skip the extensions section */
        if(ctx->phase == 4) {
            ASN_DEBUG("skip_unknown(%d, %ld)",
                      tcv, (long)ctx->left);
            switch(xer_skip_unknown(tcv, &ctx->left)) {
            case -1:
                ctx->phase = 5;
                RETURN(RC_FAIL);
            case 1:
                ctx->phase = 3;
                /* Fall through */
            case 0:
                XER_ADVANCE(ch_size);
                continue;
            case 2:
                ctx->phase = 3;
                break;
            }
        }

        switch(tcv) {
        case XCT_BOTH:
            break;  /* No CHOICE? */
        case XCT_CLOSING:
            if(ctx->phase != 3)
                break;
            XER_ADVANCE(ch_size);
            ctx->phase = 5;  /* Phase out */
            RETURN(RC_OK);
        case XCT_OPENING:
            if(ctx->phase == 0) {
                XER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }
            /* Fall through */
        case XCT_UNKNOWN_OP:
        case XCT_UNKNOWN_BO:

            if(ctx->phase != 1)
                break;  /* Really unexpected */

            /*
             * Search which inner member corresponds to this tag.
             */
            for(edx = 0; edx < td->elements_count; edx++) {
                elm = &td->elements[edx];
                tcv = xer_check_tag(buf_ptr,ch_size,elm->name);
                switch(tcv) {
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
            if(specs->ext_start != -1) {
                ASN_DEBUG("Got anticipated extension");
                /*
                 * Check for (XCT_BOTH or XCT_UNKNOWN_BO)
                 * By using a mask. Only record a pure
                 * <opening> tags.
                 */
                if(tcv & XCT_CLOSING) {
                    /* Found </extension> without body */
                    ctx->phase = 3;  /* Terminating */
                } else {
                    ctx->left = 1;
                    ctx->phase = 4;  /* Skip ...'s */
                }
                XER_ADVANCE(ch_size);
                continue;
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected XML tag [%c%c%c%c] in CHOICE [%s]"
                  " (ph=%d, tag=%s)",
                  ch_size>0?((const uint8_t *)buf_ptr)[0]:'?',
                  ch_size>1?((const uint8_t *)buf_ptr)[1]:'?',
                  ch_size>2?((const uint8_t *)buf_ptr)[2]:'?',
                  ch_size>3?((const uint8_t *)buf_ptr)[3]:'?',
                  td->name, ctx->phase, xml_tag);
        break;
    }

    ctx->phase = 5;  /* Phase out, just in case */
    RETURN(RC_FAIL);
}

asn_enc_rval_t
CHOICE_encode_xer(const asn_TYPE_descriptor_t *td, const void *sptr, int ilevel,
                  enum xer_encoder_flags_e flags, asn_app_consume_bytes_f *cb,
                  void *app_key) {
    const asn_CHOICE_specifics_t *specs =
        (const asn_CHOICE_specifics_t *)td->specifics;
    asn_enc_rval_t er = {0,0,0};
    unsigned present = 0;

    if(!sptr)
        ASN__ENCODE_FAILED;

    /*
     * Figure out which CHOICE element is encoded.
     */
    present = _fetch_present_idx(sptr, specs->pres_offset,specs->pres_size);

    if(present == 0 || present > td->elements_count) {
        ASN__ENCODE_FAILED;
    } else {
        asn_enc_rval_t tmper = {0,0,0};
        asn_TYPE_member_t *elm = &td->elements[present-1];
        const void *memb_ptr = NULL;
        const char *mname = elm->name;
        unsigned int mlen = strlen(mname);

        if(elm->flags & ATF_POINTER) {
            memb_ptr =
                *(const void *const *)((const char *)sptr + elm->memb_offset);
            if(!memb_ptr) ASN__ENCODE_FAILED;
        } else {
            memb_ptr = (const void *)((const char *)sptr + elm->memb_offset);
        }

        er.encoded = 0;

        if(!(flags & XER_F_CANONICAL)) ASN__TEXT_INDENT(1, ilevel);
        ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

        tmper = elm->type->op->xer_encoder(elm->type, memb_ptr,
                                           ilevel + 1, flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;

        ASN__CALLBACK3("</", 2, mname, mlen, ">", 1);
    }

    if(!(flags & XER_F_CANONICAL)) ASN__TEXT_INDENT(1, ilevel - 1);

    ASN__ENCODED_OK(er);
cb_failed:
    ASN__ENCODE_FAILED;
}
