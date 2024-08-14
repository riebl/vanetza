/*
 * Copyright (c) 2003, 2004 X/IO Labs, xiolabs.com.
 * Copyright (c) 2003, 2004, 2005 Lev Walkin <vlm@lionet.info>.
 * 	All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include "asn_system.h"
#include "jer_support.h"

/* Parser states */
typedef enum {
    ST_TEXT,
    ST_KEY,
    ST_KEY_BODY,
    ST_COLON,
    ST_VALUE,
    ST_VALUE_BODY,
    ST_ARRAY_VALUE,
    ST_ARRAY_VALUE_BODY,
    ST_END
} pstate_e;

static const int _charclass[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, /* 01234567 89
                                                                 */
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /*  ABCDEFG HIJKLMNO */
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0, /* PQRSTUVW XYZ      */
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /*  abcdefg hijklmno */
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0  /* pqrstuvw xyz      */
};
#define WHITESPACE(c) (_charclass[(unsigned char)(c)] == 1)
#define ALNUM(c) (_charclass[(unsigned char)(c)] >= 2)
#define ALPHA(c) (_charclass[(unsigned char)(c)] == 3)

/* Aliases for characters, ASCII/UTF-8 */
#define CCOLON 0x3a /* ':' */
#define LCBRAC 0x7b /* '{' */
#define RCBRAC 0x7d /* '}' */
#define CQUOTE 0x22 /* '"' */
#define LSBRAC 0x5b /* '[' */
#define RSBRAC 0x5d /* ']' */
#define CCOMMA 0x2c /* ',' */

/* Invoke token callback */
#define TOKEN_CB_CALL(type, _ns, _current_too, _final)  \
    do {                                                \
        int _ret;                                       \
        pstate_e ns = _ns;                              \
        ssize_t _sz = (p - chunk_start) + _current_too; \
        if(!_sz) {                                      \
            /* Shortcut */                              \
            state = _ns;                                \
            break;                                      \
        }                                               \
        _ret = cb(type, chunk_start, _sz, key);         \
        if(_ret < _sz) {                                \
            if(_current_too && _ret == -1) state = ns;  \
            goto finish;                                \
        }                                               \
        chunk_start = p + _current_too;                 \
        state = ns;                                     \
    } while(0)

#define TOKEN_CB(_type, _ns, _current_too) \
    TOKEN_CB_CALL(_type, _ns, _current_too, 0)

#define PJSON_KEY_FINAL_CHUNK_TYPE PJSON_KEY_END
#define PJSON_VALUE_FINAL_CHUNK_TYPE PJSON_VALUE_END

#define TOKEN_CB_FINAL(_type, _ns, _current_too) \
    TOKEN_CB_CALL(_type##_FINAL_CHUNK_TYPE, _ns, _current_too, 1)

/*
 * Parser itself
 */
ssize_t
pjson_parse(int *stateContext, const void *jsonbuf, size_t size,
            pjson_callback_f *cb, void *key) {
    pstate_e state = (pstate_e)*stateContext;
    const char *chunk_start = (const char *)jsonbuf;
    const char *p = chunk_start;
    const char *end = p + size;

    int include = 0;
    int in_string = 0;
    int escaped = 0;

    for(; p < end; p++) {
        int C = *(const unsigned char *)p;
        switch(state) {
        case ST_TEXT:
            /*
             * Initial state: we're in the middle of some text,
             * or just have started.
             */

            if(C == CQUOTE && !escaped) { /* " */
                in_string = !in_string;
                break;
            } else {
                if (C == '\\') {
                    escaped = !escaped;
                    break;
                } else {
                    escaped = 0;
                }
            }

            if (!in_string) {
                switch(C) {
                case LCBRAC:
                    /* We're now in an object */
                    TOKEN_CB(PJSON_DLM, ST_KEY, 1);
                    break;
                case LSBRAC:
                    /* We're now in an array */
                    TOKEN_CB(PJSON_DLM, ST_ARRAY_VALUE, 1);
                    break;

                case RSBRAC:
                    include = !(p - chunk_start);
                    TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, include);
                    break;
                case RCBRAC:
                    include = !(p - chunk_start);
                    TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, include);
                    break;
                case CCOMMA:
                    TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, 0);
                    break;
                default:
                    break;
                }
            }
            break;

        case ST_KEY: /* Looking for key */
            switch(C) {
            case RCBRAC: /* Empty object { } */
                TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, 1);
                break;
            case CQUOTE: /* Key start */
                TOKEN_CB(PJSON_TEXT, ST_KEY_BODY, 0);
                break;
            default:
                break;
            }
            break;

        case ST_KEY_BODY: /* Inside key */
            switch(C) {
            case CQUOTE: /* Key end */
                TOKEN_CB_FINAL(PJSON_KEY, ST_COLON, 1);
                break;
            default:
                break;
            }
            break;

		case ST_COLON: /* Looking for colon */
			switch(C) {
			case CCOLON:
                state = ST_VALUE;
				break;
			default:
                break;
			}
			break;

		case ST_VALUE: /* Looking for value */
            if (WHITESPACE(C)) {
                break;
            } else {
                switch(C) {
                case CCOMMA:
                    TOKEN_CB(PJSON_DLM, ST_KEY, 1);
                    break;
                case RCBRAC:
                    TOKEN_CB(PJSON_DLM, ST_END, 1);
                    break;
                case RSBRAC:
                    TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, 1);
                    break;
                default:
                    TOKEN_CB(PJSON_TEXT, ST_VALUE_BODY, 0);
                    break;
                }
            }
			break;

        case ST_VALUE_BODY: /* Inside value */
            switch(C)  {
            case RCBRAC:
                TOKEN_CB_FINAL(PJSON_VALUE, ST_END, 0);
                break;
            case CCOMMA:
                include = !(p - chunk_start);
                TOKEN_CB_FINAL(PJSON_VALUE, ST_KEY, include);
                break;
            default:
                break;
            }
            break;

        case ST_ARRAY_VALUE: /* Looking for array value */
            if (WHITESPACE(C)) {
                break;
            } else {
                switch(C) {
                case LCBRAC:
                    TOKEN_CB(PJSON_DLM, ST_ARRAY_VALUE, 1);
                    break;
                case CCOMMA:
                    TOKEN_CB(PJSON_DLM, ST_ARRAY_VALUE, 1);
                    break;
                case LSBRAC:
                    TOKEN_CB(PJSON_DLM, ST_ARRAY_VALUE, 1);
                    break;
                case RSBRAC:
                    TOKEN_CB(PJSON_DLM, ST_END, 1);
                    break;
                default:
                    TOKEN_CB(PJSON_TEXT, ST_ARRAY_VALUE_BODY, 0);
                    break;
                }
            }
            break;

        case ST_ARRAY_VALUE_BODY: /* Inside array value */
            switch(C)  {
            case RSBRAC:
                include = !(p - chunk_start);
                TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, include);
                break;
            case CCOMMA:
                include = !(p - chunk_start);
                if (!include) {
                    TOKEN_CB_FINAL(PJSON_VALUE, ST_ARRAY_VALUE, 0);
                } else {
                    TOKEN_CB(PJSON_DLM, ST_ARRAY_VALUE, 0);
                }
                break;
            default:
                break;
            }
            break;

        case ST_END: /* End */
            switch (C)  {
            case RCBRAC:
                TOKEN_CB_FINAL(PJSON_VALUE, ST_TEXT, 1);
                break;
            default:
                break;
            }
            break;
        } /* switch(*ptr) */
    }     /* for() */

    /*
     * Flush the partially processed chunk, state permitting.
     */
    if(p - chunk_start) {
        switch (state) {
        case ST_TEXT:
            TOKEN_CB_FINAL(PJSON_VALUE, state, 0);
            break;
        default:
            break;
        }
    }

finish:
    *stateContext = (int)state;
    return chunk_start - (const char *)jsonbuf;
}
