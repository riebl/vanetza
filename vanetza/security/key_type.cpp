#include <vanetza/security/key_type.hpp>

namespace vanetza
{
namespace security
{

std::size_t key_length(KeyType key_type)
{
    switch (key_type)
    {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1:
            return 32;
        case KeyType::BrainpoolP384r1:
            return 48;
        default:
            return 0;
    }
}

} // namespace security
} // namespace vanetza
