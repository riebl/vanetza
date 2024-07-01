#include <stdlib.h>

static size_t max_size = 4096;

void* vanetza_asn1c_malloc(size_t size)
{
    if (size <= max_size)
        return malloc(size);
    else
        return NULL;
}

void* vanetza_asn1c_calloc(size_t nmemb, size_t size)
{
    if (nmemb * size <= max_size)
        return calloc(nmemb, size);
    else
        return NULL;
}

void* vanetza_asn1c_realloc(void* ptr, size_t size)
{
    if (size <= max_size)
        return realloc(ptr, size);
    else
        return NULL;
}
