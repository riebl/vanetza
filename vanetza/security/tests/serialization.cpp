#include <vanetza/security/tests/serialization.hpp>
#include <cstdio>

namespace vanetza
{
namespace security
{

ByteBuffer buffer_from_hexstring(const char* string)
{
    unsigned n;
    const size_t half_string_length = strlen(string) / 2;
    ByteBuffer buf(half_string_length);
    for (size_t i = 0; i < half_string_length; ++i) {
        sscanf(string + 2 * i, "%2X", &n);
        buf[i] = n;
    }
    return buf;
}

} // namespace security
} // namespace vanetza
