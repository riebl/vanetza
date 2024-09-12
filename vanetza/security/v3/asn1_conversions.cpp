#include <vanetza/security/v3/asn1_conversions.hpp>
#include <algorithm>
#include <cstring>

namespace vanetza
{
namespace security
{
namespace v3
{

HashedId8 convert(const Vanetza_Security_HashedId8_t& in)
{
    HashedId8 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;
}

} // namespace v3

HashedId8 create_hashed_id8(const Vanetza_Security_HashedId8_t& in)
{
    HashedId8 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;    
}

HashedId3 create_hashed_id3(const Vanetza_Security_HashedId3_t& in)
{
    HashedId3 out;
    std::memcpy(out.data(), in.buf, std::min(out.size(), in.size));
    return out;
}

} // namespace security
} // namespace vanetza
