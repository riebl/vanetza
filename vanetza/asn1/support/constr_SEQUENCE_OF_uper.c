/*
 * Copyright (c) 2017 Lev Walkin <vlm@lionet.info>.
 * All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_internal.h"
#include "constr_SEQUENCE_OF.h"
#include "asn_SEQUENCE_OF.h"

asn_enc_rval_t
SEQUENCE_OF_encode_uper(const asn_TYPE_descriptor_t *td,
                        const asn_per_constraints_t *constraints,
                        const void *sptr, asn_per_outp_t *po) {
    const asn_anonymous_sequence_ *list;
	const asn_per_constraint_t *ct;
	asn_enc_rval_t er = {0,0,0};
	const asn_TYPE_member_t *elm = td->elements;
	size_t encoded_edx;

	if(!sptr) ASN__ENCODE_FAILED;
    list = _A_CSEQUENCE_FROM_VOID(sptr);

    er.encoded = 0;

	ASN_DEBUG("Encoding %s as SEQUENCE OF (%d)", td->name, list->count);

    if(constraints) ct = &constraints->size;
    else if(td->encoding_constraints.per_constraints)
        ct = &td->encoding_constraints.per_constraints->size;
    else ct = 0;

    /* If extensible constraint, check if size is in root */
    if(ct) {
        int not_in_root =
            (list->count < ct->lower_bound || list->count > ct->upper_bound);
        ASN_DEBUG("lb %ld ub %ld %s", ct->lower_bound, ct->upper_bound,
                  ct->flags & APC_EXTENSIBLE ? "ext" : "fix");
        if(ct->flags & APC_EXTENSIBLE) {
            /* Declare whether size is in extension root */
            if(per_put_few_bits(po, not_in_root, 1)) ASN__ENCODE_FAILED;
            if(not_in_root) ct = 0;
        } else if(not_in_root && ct->effective_bits >= 0) {
            ASN__ENCODE_FAILED;
        }

    }

    if(ct && ct->effective_bits >= 0) {
        /* X.691, #19.5: No length determinant */
        if(per_put_few_bits(po, list->count - ct->lower_bound,
                            ct->effective_bits))
            ASN__ENCODE_FAILED;
    } else if(list->count == 0) {
        /* When the list is empty add only the length determinant
         * X.691, #20.6 and #11.9.4.1
         */
        if (uper_put_length(po, 0, 0)) {
            ASN__ENCODE_FAILED;
        }
        ASN__ENCODED_OK(er);
    }

    for(encoded_edx = 0; (ssize_t)encoded_edx < list->count;) {
        ssize_t may_encode;
        size_t edx;
        int need_eom = 0;

        if(ct && ct->effective_bits >= 0) {
            may_encode = list->count;
        } else {
            may_encode =
                uper_put_length(po, list->count - encoded_edx, &need_eom);
            if(may_encode < 0) ASN__ENCODE_FAILED;
        }

        for(edx = encoded_edx; edx < encoded_edx + may_encode; edx++) {
            void *memb_ptr = list->array[edx];
            if(!memb_ptr) ASN__ENCODE_FAILED;
            er = elm->type->op->uper_encoder(
                elm->type, elm->encoding_constraints.per_constraints, memb_ptr,
                po);
            if(er.encoded == -1) ASN__ENCODE_FAILED;
        }

        if(need_eom && uper_put_length(po, 0, 0))
            ASN__ENCODE_FAILED; /* End of Message length */

        encoded_edx += may_encode;
    }

	ASN__ENCODED_OK(er);
}
