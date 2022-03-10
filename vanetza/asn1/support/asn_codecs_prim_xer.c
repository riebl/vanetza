/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "asn_codecs_prim.h"

/*
 * Local internal type passed around as an argument.
 */
struct xdp_arg_s {
    const asn_TYPE_descriptor_t *type_descriptor;
    void *struct_key;
    xer_primitive_body_decoder_f *prim_body_decoder;
    int decoded_something;
    int want_more;
};

/*
 * Since some kinds of primitive values can be encoded using value-specific
 * tags (<MINUS-INFINITY>, <enum-element>, etc), the primitive decoder must
 * be supplied with such tags to parse them as needed.
 */
static int
xer_decode__unexpected_tag(void *key, const void *chunk_buf, size_t chunk_size) {
    struct xdp_arg_s *arg = (struct xdp_arg_s *)key;
    enum xer_pbd_rval bret;

    /*
     * The chunk_buf is guaranteed to start at '<'.
     */
    assert(chunk_size && ((const char *)chunk_buf)[0] == 0x3c);

    /*
     * Decoding was performed once already. Prohibit doing it again.
    */
    if(arg->decoded_something)
        return -1;

    bret = arg->prim_body_decoder(arg->type_descriptor,
                                  arg->struct_key, chunk_buf,
                                  chunk_size);
    switch(bret) {
    case XPBD_SYSTEM_FAILURE:
    case XPBD_DECODER_LIMIT:
    case XPBD_BROKEN_ENCODING:
        break;
    case XPBD_BODY_CONSUMED:
        /* Tag decoded successfully */
        arg->decoded_something = 1;
        /* Fall through */
    case XPBD_NOT_BODY_IGNORE:  /* Safe to proceed further */
        return 0;
    }

    return -1;
}

static ssize_t
xer_decode__primitive_body(void *key, const void *chunk_buf, size_t chunk_size, int have_more) {
    struct xdp_arg_s *arg = (struct xdp_arg_s *)key;
    enum xer_pbd_rval bret;
    size_t lead_wsp_size;

    if(arg->decoded_something) {
        if(xer_whitespace_span(chunk_buf, chunk_size) == chunk_size) {
            /*
             * Example:
             * "<INTEGER>123<!--/--> </INTEGER>"
             *                      ^- chunk_buf position.
             */
            return chunk_size;
        }
        /*
         * Decoding was done once already. Prohibit doing it again.
         */
        return -1;
    }

    if(!have_more) {
        /*
         * If we've received something like "1", we can't really
         * tell whether it is really `1` or `123`, until we know
         * that there is no more data coming.
         * The have_more argument will be set to 1 once something
         * like this is available to the caller of this callback:
         * "1<tag_start..."
         */
        arg->want_more = 1;
        return -1;
    }

    lead_wsp_size = xer_whitespace_span(chunk_buf, chunk_size);
    chunk_buf   = (chunk_buf == NULL)? NULL : ((const char *)chunk_buf + lead_wsp_size);
    chunk_size -= lead_wsp_size;

    bret = arg->prim_body_decoder(arg->type_descriptor,
                                  arg->struct_key, chunk_buf,
                                  chunk_size);
    switch(bret) {
    case XPBD_SYSTEM_FAILURE:
    case XPBD_DECODER_LIMIT:
    case XPBD_BROKEN_ENCODING:
        break;
    case XPBD_BODY_CONSUMED:
        /* Tag decoded successfully */
        arg->decoded_something = 1;
        /* Fall through */
    case XPBD_NOT_BODY_IGNORE:  /* Safe to proceed further */
        return lead_wsp_size + chunk_size;
    }

    return -1;
}

asn_dec_rval_t
xer_decode_primitive(const asn_codec_ctx_t *opt_codec_ctx,
                     const asn_TYPE_descriptor_t *td, void **sptr,
                     size_t struct_size, const char *opt_mname,
                     const void *buf_ptr, size_t size,
                     xer_primitive_body_decoder_f *prim_body_decoder) {
    const char *xml_tag = opt_mname ? opt_mname : td->xml_tag;
    asn_struct_ctx_t s_ctx;
    struct xdp_arg_s s_arg;
    asn_dec_rval_t rc;

    /*
     * Create the structure if does not exist.
     */
    if(!*sptr) {
        *sptr = CALLOC(1, struct_size);
        if(!*sptr) ASN__DECODE_FAILED;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
    s_arg.type_descriptor = td;
    s_arg.struct_key = *sptr;
    s_arg.prim_body_decoder = prim_body_decoder;
    s_arg.decoded_something = 0;
    s_arg.want_more = 0;

    rc = xer_decode_general(opt_codec_ctx, &s_ctx, &s_arg,
                            xml_tag, buf_ptr, size,
                            xer_decode__unexpected_tag,
                            xer_decode__primitive_body);
    switch(rc.code) {
    case RC_OK:
        if(!s_arg.decoded_something) {
            char ch;
            ASN_DEBUG("Primitive body is not recognized, "
                      "supplying empty one");
            /*
             * Decoding opportunity has come and gone.
             * Where's the result?
             * Try to feed with empty body, see if it eats it.
             */
            if(prim_body_decoder(s_arg.type_descriptor,
                s_arg.struct_key, &ch, 0)
                    != XPBD_BODY_CONSUMED) {
                /*
                 * This decoder does not like empty stuff.
                 */
                ASN__DECODE_FAILED;
            }
        }
        break;
    case RC_WMORE:
        /*
         * Redo the whole thing later.
         * We don't have a context to save intermediate parsing state.
         */
        rc.consumed = 0;
        break;
    case RC_FAIL:
        rc.consumed = 0;
        if(s_arg.want_more)
            rc.code = RC_WMORE;
        else
            ASN__DECODE_FAILED;
        break;
    }
    return rc;
}
