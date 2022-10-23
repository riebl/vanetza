#ifndef CE45A952_0EE7_4D20_82CB_D42BF87F5B15
#define CE45A952_0EE7_4D20_82CB_D42BF87F5B15

#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

using HashedId8 = std::array<uint8_t, 8>;
using HashedId3 = std::array<uint8_t, 3>;

HashedId3 truncate(const HashedId8&);

} // namespace security
} // namespace vanetz

#endif /* CE45A952_0EE7_4D20_82CB_D42BF87F5B15 */
