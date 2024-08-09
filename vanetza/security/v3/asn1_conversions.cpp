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
} // namespace security
} // namespace vanetza
