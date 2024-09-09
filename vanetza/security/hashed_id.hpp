#ifndef CE45A952_0EE7_4D20_82CB_D42BF87F5B15
#define CE45A952_0EE7_4D20_82CB_D42BF87F5B15

#include <vanetza/security/sha.hpp>
#include <array>
#include <cstdint>
#include <functional>
#include <string>

namespace vanetza
{
namespace security
{

using HashedId8 = std::array<uint8_t, 8>;
using HashedId3 = std::array<uint8_t, 3>;

HashedId3 truncate(const HashedId8&);

HashedId8 create_hashed_id8(const Sha256Digest&);
HashedId8 create_hashed_id8(const Sha384Digest&);

std::string to_string(const vanetza::security::HashedId8&);

} // namespace security
} // namespace vanetza

namespace std
{
/// std::hash specialization for HashedId8
template<> struct hash<vanetza::security::HashedId8>
{
    size_t operator()(const vanetza::security::HashedId8&) const;
};
} // namespace std

#endif /* CE45A952_0EE7_4D20_82CB_D42BF87F5B15 */
