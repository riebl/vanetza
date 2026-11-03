#include <vanetza/security/aes.hpp>

namespace vanetza
{
namespace security
{

Aes128Key::~Aes128Key()
{
    // volatile writes are not optimised away although the key is not read afterwards
    volatile std::uint8_t* octet = octets.data();
    for (std::size_t i = 0; i < octets.size(); ++i) {
        octet[i] = 0;
    }
}

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
