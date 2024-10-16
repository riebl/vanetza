/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SET_OF.h"

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

#undef JER_ADVANCE
#define JER_ADVANCE(num_bytes)                    \
    do {                                          \
        size_t num = num_bytes;                   \
        buf_ptr = ((const char *)buf_ptr) + num;  \
        size -= num;                              \
        consumed_myself += num;                   \
    } while(0)

/*
 * Decode the JER (JSON) data.
 */
asn_dec_rval_t
SET_OF_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                  const asn_TYPE_descriptor_t *td,
                  const asn_jer_constraints_t *constraints,
                  void **struct_ptr, const void *buf_ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *element = td->elements;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval = {RC_OK, 0};  /* Return value from a decoder */
    ssize_t consumed_myself = 0;       /* Consumed bytes from ptr */

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
     * Phases of JER/JSON processing:
     * Phase 0: Check that the opening tag matches our expectations.
     * Phase 1: Processing body and reacting on closing token.
     * Phase 2: Processing inner type.
     */
    for(; ctx->phase <= 2;) {
        pjer_chunk_type_e ch_type;  /* JER chunk type */
        ssize_t ch_size;            /* Chunk size */
        jer_check_sym_e scv;        /* Tag check value */

        /*
         * Go inside the inner member of a set.
         */
        if(ctx->phase == 2) {
            asn_dec_rval_t tmprval = {RC_OK, 0};

            /* Invoke the inner type decoder, m.b. multiple times */
            ASN_DEBUG("JER/SET OF element [%s]", 
                    (*element->name) ? element->name : element->type->xml_tag);
            tmprval = element->type->op->jer_decoder(opt_codec_ctx,
                                                     element->type,
                                                     element->encoding_constraints.jer_constraints,
                                                     &ctx->ptr,
                                                     buf_ptr, size);
            if(tmprval.code == RC_OK) {
                asn_anonymous_set_ *list = _A_SET_FROM_VOID(st);
                if(ASN_SET_ADD(list, ctx->ptr) != 0)
                    RETURN(RC_FAIL);
                ctx->ptr = 0;
                JER_ADVANCE(tmprval.consumed);
            } else {
                JER_ADVANCE(tmprval.consumed);
                RETURN(tmprval.code);
            }

            ctx->phase = 1;  /* Back to body processing */
            ASN_DEBUG("JER/SET OF phase => %d", ctx->phase);
            /* Fall through */
        }

        /*
         * Get the next part of the JSON stream.
         */
        ch_size = jer_next_token(&ctx->context,
                                 buf_ptr, size, &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                RETURN(RC_WMORE);
            case PJER_TEXT:  
                JER_ADVANCE(ch_size);
                continue;

            case PJER_DLM:
            case PJER_VALUE:
            case PJER_KEY:
                break;  /* Check the rest down there */
            }
        }

        scv = jer_check_sym(buf_ptr, ch_size, NULL);
        ASN_DEBUG("JER/SET OF: scv = %d, ph=%d t=%s",
                  scv, ctx->phase, td->name);
        switch(scv) {
        case JCK_AEND:
            if(ctx->phase == 0) break;
            ctx->phase = 0;

            if(ctx->phase == 0) {
                /* No more things to decode */
                JER_ADVANCE(ch_size);
                ctx->phase = 3;  /* Phase out */
                RETURN(RC_OK);
            }
            /* Fall through */
        case JCK_OEND:
        case JCK_KEY:
        case JCK_COMMA:
        case JCK_ASTART:
            if(ctx->phase == 0) {
                JER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }
            /* Fall through */
        case JCK_UNKNOWN:
        case JCK_OSTART:
            ASN_DEBUG("JER/SET OF: scv=%d, ph=%d", scv, ctx->phase);
            if(ctx->phase == 1) {
                /*
                 * Process a single possible member.
                 */
                ctx->phase = 2;
                continue;
            }
            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected JSON key in SET OF");
        break;
    }

    ctx->phase = 3;  /* "Phase out" on hard failure */
    RETURN(RC_FAIL);
}

asn_enc_rval_t
SET_OF_encode_jer(const asn_TYPE_descriptor_t *td, 
                  const asn_jer_constraints_t* constraints, const void *sptr, 
                  int ilevel, enum jer_encoder_flags_e flags, 
                  asn_app_consume_bytes_f *cb, void *app_key) {
    asn_enc_rval_t er = {0,0,0};
    const asn_SET_OF_specifics_t *specs = (const asn_SET_OF_specifics_t *)td->specifics;
    const asn_TYPE_member_t *elm = td->elements;
    const asn_anonymous_set_ *list = _A_CSET_FROM_VOID(sptr);
    int jmin = (flags & JER_F_MINIFIED);
    int i;

    if(!sptr) ASN__ENCODE_FAILED;

    er.encoded = 0;
    ASN__CALLBACK("[", 1);

    for(i = 0; i < list->count; i++) {
        asn_enc_rval_t tmper = {0,0,0};

        void *memb_ptr = list->array[i];
        if(!memb_ptr) continue;

        if(!jmin) ASN__TEXT_INDENT(1, ilevel + 1);
        tmper = elm->type->op->jer_encoder(elm->type, 
                                           elm->encoding_constraints.jer_constraints, 
                                           memb_ptr,
                                           ilevel + (specs->as_XMLValueList != 2),
                                           flags, cb, app_key);
        if(tmper.encoded == -1) return tmper;
        er.encoded += tmper.encoded;
        if(tmper.encoded == 0 && specs->as_XMLValueList) {
            const char *name = elm->type->xml_tag;
            size_t len = strlen(name);
            ASN__CALLBACK3("\"", 1, name, len, "\"", 1);
        }
        if (i != list->count - 1) {
          ASN__CALLBACK(",", 1);
        }
    }

    if(!jmin) ASN__TEXT_INDENT(1, ilevel);
    ASN__CALLBACK("]", 1);

    goto cleanup;
cb_failed:
    ASN__ENCODE_FAILED;
cleanup:
    ASN__ENCODED_OK(er);
}
