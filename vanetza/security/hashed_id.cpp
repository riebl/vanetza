#include <vanetza/security/hashed_id.hpp>
#include <boost/container_hash/hash.hpp>
#include <algorithm>
#include <cassert>

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

} // namespace security
} // namespace vanetza

namespace std
{

size_t hash<vanetza::security::HashedId8>::operator()(const vanetza::security::HashedId8& hid8) const
{
    size_t seed = 0;
    for (uint8_t octet : hid8) {
        boost::hash_combine(seed, octet);
    }
    return seed;
}

} // namespace std