#include <vanetza/security/tests/web_validator.hpp>
#include <vanetza/security/serialization.hpp>
#include <cstdio>

namespace vanetza
{
namespace security
{

void stream_from_string(std::stringstream& stream, const char *string)
{
    unsigned n;
    OutputArchive oa(stream);
    for (size_t i = 0; i < strlen(string) / 2; i++) {
        sscanf(string + 2 * i, "%2X", &n);
        uint8_t tmp = (char) n;
        oa << tmp;
    }
}

void byteBuffer_from_string(ByteBuffer& buf, const char *string)
{
    unsigned n;
    for (size_t i = 0; i < strlen(string) / 2; i++) {
        sscanf(string + 2 * i, "%2X", &n);
        uint8_t tmp = (char) n;
        buf.push_back(tmp);
    }
}

} // namespace security
} // namespace vanetza
