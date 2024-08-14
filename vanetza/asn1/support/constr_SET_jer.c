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

/*
 * Check whether we are inside the extensions group.
 */
#define IN_EXTENSION_GROUP(specs, memb_idx)                \
    ((specs)->first_extension >= 0                         \
     && (unsigned)(specs)->first_extension <= (memb_idx))

#undef JER_ADVANCE
#define JER_ADVANCE(num_bytes)            \
    do {                                  \
        size_t num = (num_bytes);         \
        ptr = ((const char *)ptr) + num;  \
        size -= num;                      \
        consumed_myself += num;           \
    } while(0)

/*
 * Decode the JER (JSON) data.
 */
asn_dec_rval_t
SET_decode_jer(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td, void **struct_ptr,
                    const void *ptr, size_t size) {
    /*
     * Bring closer parts of structure description.
     */
    const asn_SET_specifics_t *specs
        = (const asn_SET_specifics_t *)td->specifics;
    asn_TYPE_member_t *elements = td->elements;

    /*
     * ... and parts of the structure being constructed.
     */
    void *st = *struct_ptr;  /* Target structure. */
    asn_struct_ctx_t *ctx;   /* Decoder context */

    asn_dec_rval_t rval;          /* Return value from a decoder */
    ssize_t consumed_myself = 0;  /* Consumed bytes from ptr */
    ssize_t edx;                  /* Element index */

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
     * Phase 0: Check that the key matches our expectations.
     * Phase 1: Processing body and reacting on closing key.
     * Phase 2: Processing inner type.
     * Phase 3: Skipping unknown extensions.
     * Phase 4: PHASED OUT
     */
    for(edx = ctx->step; ctx->phase <= 3;) {
        pjer_chunk_type_e ch_type;  /* JER chunk type */
        ssize_t ch_size;            /* Chunk size */
        jer_check_sym_e scv;        /* Tag check value */
        asn_TYPE_member_t *elm;


        /*
         * Go inside the inner member of a sequence.
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
            tmprval = elm->type->op->jer_decoder(opt_codec_ctx,
                                                 elm->type, memb_ptr2,
                                                 ptr, size);
            JER_ADVANCE(tmprval.consumed);
            if(tmprval.code != RC_OK)
                RETURN(tmprval.code);
            ctx->phase = 1;  /* Back to body processing */
            ASN_SET_MKPRESENT((char *)st + specs->pres_offset, edx);
            ASN_DEBUG("JER/SET phase => %d", ctx->phase);
            /* Fall through */
        }

        /*
         * Get the next part of the JSON stream.
         */
        ch_size = jer_next_token(&ctx->context, ptr, size,
            &ch_type);
        if(ch_size == -1) {
            RETURN(RC_FAIL);
        } else {
            switch(ch_type) {
            case PJER_WMORE:
                RETURN(RC_WMORE);

            case PJER_TEXT:  /* Ignore free-standing text */
                JER_ADVANCE(ch_size);  /* Skip silently */
                continue;

            case PJER_DLM:
            case PJER_VALUE:  /* Ignore free-standing text */
            case PJER_KEY:
                break;  /* Check the rest down there */
            }
        }

        scv = jer_check_sym(ptr, ch_size, NULL);
        ASN_DEBUG("JER/SET: scv = %d, ph=%d [%s]",
                  scv, ctx->phase, td->name);


        /* Skip the extensions section */
        if(ctx->phase == 3) {
            switch(jer_skip_unknown(scv, &ctx->left)) {
            case -1:
                ctx->phase = 4;
                RETURN(RC_FAIL);
            case 0:
                JER_ADVANCE(ch_size);
                continue;
            case 1:
                JER_ADVANCE(ch_size);
                ctx->phase = 1;
                continue;
            case 2:
                ctx->phase = 1;
                break;
            }
        }

        switch(scv) {
        case JCK_OEND:
            if(ctx->phase == 0) break;
            ctx->phase = 0;

            if(_SET_is_populated(td, st)) {
                JER_ADVANCE(ch_size);
                JER_ADVANCE(jer_whitespace_span(ptr, size)); 
                ctx->phase = 4;  /* Phase out */
                RETURN(RC_OK);
            } else {
                ASN_DEBUG("Premature end of JER SET");
                RETURN(RC_FAIL);
            }

        case JCK_COMMA:
            JER_ADVANCE(ch_size);
            continue;

        case JCK_OSTART:
            if(ctx->phase == 0) {
                JER_ADVANCE(ch_size);
                ctx->phase = 1;  /* Processing body phase */
                continue;
            }

            /* Fall through */
        case JCK_KEY:
        case JCK_UNKNOWN:
            ASN_DEBUG("JER/SET: scv=%d, ph=%d, edx=%" ASN_PRI_SIZE "",
                      scv, ctx->phase, edx);
            if(ctx->phase != 1) {
                break;  /* Really unexpected */
            }

            if (td->elements_count == 0) {
                JER_ADVANCE(ch_size);
                continue;
            }

            if(edx < td->elements_count) {
                /*
                 * We have to check which member is next.
                 */
                for(edx = 0; edx < td->elements_count; edx++) {
                    elm = &elements[edx];
                    scv = jer_check_sym(ptr, ch_size, elm->name);
                    switch (scv) {
                    case JCK_KEY:
                        ctx->step = edx;
                        ctx->phase = 2;

                        JER_ADVANCE(ch_size); /* skip key */
                        /* skip colon */
                        ch_size = jer_next_token(&ctx->context, ptr, size,
                                &ch_type);
                        if(ch_size == -1) {
                            RETURN(RC_FAIL);
                        } else {
                            switch(ch_type) {
                                case PJER_WMORE:
                                    RETURN(RC_WMORE);
                                case PJER_TEXT:  
                                    JER_ADVANCE(ch_size);
                                    break;
                                default:
                                    RETURN(RC_FAIL);
                            }
                        }
                        break;
                    case JCK_UNKNOWN:
                        continue;
                    default:
                        edx = td->elements_count;
                        break; /* Phase out */
                    }
                    break;
                }
                if(edx != td->elements_count)
                    continue;
            } else {
                ASN_DEBUG("Out of defined members: %" ASN_PRI_SIZE "/%u",
                          edx, td->elements_count);
            }

            /* It is expected extension */
            if(specs->extensible) {
                ASN_DEBUG("Got anticipated extension");
                ctx->left = 1;
                ctx->phase = 3;  /* Skip ...'s */
                JER_ADVANCE(ch_size);
                continue;
            }

            /* Fall through */
        default:
            break;
        }

        ASN_DEBUG("Unexpected JSON key in SET [%c%c%c%c%c%c]",
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
