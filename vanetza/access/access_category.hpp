#ifndef ACCESS_CATEGORY_HPP_QAWSOPED
#define ACCESS_CATEGORY_HPP_QAWSOPED

#include <cstdint>
#include <iosfwd>

namespace vanetza
{
namespace access
{

/**
 * \enum AccessCategory
 * \brief AccessCategory represents packet priority at link layer
 *
 * Each enumerator's value matches the user priority UP (802.1D)
 * of the respective access category AC (802.11).
 *
 * See ETSI EN 302 663 V1.2.1 (2013-07), Table B.3
 */
enum class AccessCategory {
    BK = 1, //!< Background (lowest priority)
    BE = 3, //!< Best effort
    VI = 5, //!< Video
    VO = 7  //!< Voice (highest priority)
}; /**< \enum */

std::ostream& operator<<(std::ostream&, AccessCategory);

constexpr std::uint8_t user_priority(AccessCategory ac)
{
    return static_cast<std::uint8_t>(ac) & 0x7;
}

} // namespace access
} // namespace vanetza

#endif /* ACCESS_CATEGORY_HPP_QAWSOPED */
