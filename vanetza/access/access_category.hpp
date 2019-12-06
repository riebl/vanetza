#ifndef ACCESS_CATEGORY_HPP_QAWSOPED
#define ACCESS_CATEGORY_HPP_QAWSOPED

#include <iosfwd>

namespace vanetza
{
namespace access
{

/**
 * \file
 * \enum AccessCategory
 * \brief AccessCategory represents packet priority at link layer
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

} // namespace access
} // namespace vanetza

#endif /* ACCESS_CATEGORY_HPP_QAWSOPED */
