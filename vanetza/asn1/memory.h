#ifndef VANETZA_ASN1C_MEMORY
#define VANETZA_ASN1C_MEMORY

#include <stddef.h>

void* vanetza_asn1c_malloc(size_t size);
void* vanetza_asn1c_calloc(size_t nmemb, size_t size);
void* vanetza_asn1c_realloc(void* ptr, size_t size);

#endif /* VANETZA_ASN1C_MEMORY */