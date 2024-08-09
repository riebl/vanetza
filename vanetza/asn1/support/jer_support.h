/*
 * Copyright (c) 2003, 2004 X/IO Labs, xiolabs.com.
 * Copyright (c) 2003-2017 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#ifndef	_JER_SUPPORT_H_
#define	_JER_SUPPORT_H_

#include "asn_system.h"		/* Platform-specific types */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types of data transferred to the application.
 */
typedef enum {
	PJSON_TEXT,
	PJSON_KEY,
	PJSON_VALUE,
	PJSON_DLM,
	/* 
	 * The following chunk types are reported if the chunk
	 * terminates the specified JSON element.
	 */
	PJSON_KEY_END,	 /* Key ended */
	PJSON_VALUE_END  /* Value ended */
} pjson_chunk_type_e;

/*
 * Callback function that is called by the parser when parsed data is
 * available. The _opaque is the pointer to a field containing opaque user 
 * data specified in pxml_create() call. The chunk type is _type and the text 
 * data is the piece of buffer identified by _bufid (as supplied to
 * pxml_feed() call) starting at offset _offset and of _size bytes size. 
 * The chunk is NOT '\0'-terminated.
 */
typedef int (pjson_callback_f)(pjson_chunk_type_e _type,
	const void *_chunk_data, size_t _chunk_size, void *_key);

/*
 * Parse the given buffer as it were a chunk of XML data.
 * Invoke the specified callback each time the meaningful data is found.
 * This function returns number of bytes consumed from the buffer.
 * It will always be lesser than or equal to the specified _size.
 * The next invocation of this function must account the difference.
 */
ssize_t pjson_parse(int *_stateContext, const void *_buf, size_t _size,
	pjson_callback_f *cb, void *_key);

#ifdef __cplusplus
}
#endif

#endif	/* _JER_SUPPORT_H_ */
