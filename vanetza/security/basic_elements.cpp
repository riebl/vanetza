#include <vanetza/security/basic_elements.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <vanetza/common/byte_buffer.hpp>
#include <algorithm>
#include <cassert>
#include <chrono>

namespace vanetza
{
namespace security
{

HashedId3 truncate(const HashedId8& in)
{
    HashedId3 out;
    assert(out.size() <= in.size());
    std::copy_n(in.rbegin(), out.size(), out.rbegin());
    return out;
}

Time32 convert_time32(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using seconds = std::chrono::duration<Time32>;
    return duration_cast<seconds>(tp.time_since_epoch()).count();
}

Time64 convert_time64(const Clock::time_point& tp)
{
    using std::chrono::duration_cast;
    using microseconds = std::chrono::duration<Time64, std::micro>;
    return duration_cast<microseconds>(tp.time_since_epoch()).count();
}

void convert_bytebuffer_to_octet_string(OCTET_STRING_t* octet, const vanetza::ByteBuffer& buffer)
{
    OCTET_STRING_fromBuf(
        octet,
        reinterpret_cast<const char *>(buffer.data()),
        buffer.size()
    );
}


} // namespace security
} // namespace vanetza
