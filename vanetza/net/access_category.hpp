#ifndef ACCESS_CATEGORY_HPP_QAWSOPED
#define ACCESS_CATEGORY_HPP_QAWSOPED

#include <iosfwd>

enum class AccessCategory {
    BK = 0,
    BE = 1,
    VI = 2,
    VO = 3
};

std::ostream& operator<<(std::ostream&, AccessCategory);

#endif /* ACCESS_CATEGORY_HPP_QAWSOPED */

