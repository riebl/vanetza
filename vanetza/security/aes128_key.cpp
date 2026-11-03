#include <vanetza/security/aes128_key.hpp>

namespace vanetza
{
namespace security
{

bool operator==(const Aes128Key& lhs, const Aes128Key& rhs)
{
    return lhs.octets == rhs.octets;
}

bool operator!=(const Aes128Key& lhs, const Aes128Key& rhs)
{
    return !(lhs == rhs);
}

} // namespace security
} // namespace vanetza
