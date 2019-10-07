#ifndef ACCESS_CATEGORY_HPP_QAWSOPED
#define ACCESS_CATEGORY_HPP_QAWSOPED

#include <iosfwd>

namespace vanetza
{
namespace access
{

/* See ETSI EN 302 663 V1.2.1 (2013-07), Table B.3 */
enum class AccessCategory {
    BK = 1,
    BE = 3,
    VI = 5,
    VO = 7
};

std::ostream& operator<<(std::ostream&, AccessCategory);

} // namespace access
} // namespace vanetza

#endif /* ACCESS_CATEGORY_HPP_QAWSOPED */
