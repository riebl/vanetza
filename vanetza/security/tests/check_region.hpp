#ifndef CHECK_REGION_HPP_UFSV2RZ5
#define CHECK_REGION_HPP_UFSV2RZ5

#include <gtest/gtest.h>
#include <vanetza/security/region.hpp>
#include <vanetza/security/tests/check_visitor.hpp>
#include <boost/format.hpp>

namespace vanetza
{
namespace security
{

inline void check(const TwoDLocation& expected, const TwoDLocation& actual)
{
    EXPECT_EQ(expected.longitude, actual.longitude);
    EXPECT_EQ(expected.latitude, actual.latitude);
}

inline void check(const CircularRegion& expected, const CircularRegion& actual)
{
    SCOPED_TRACE("CiruclarRegion");
    check(expected.center, actual.center);
    EXPECT_EQ(expected.radius, actual.radius);
}

inline void check(const RectangularRegion& expected, const RectangularRegion& actual)
{
    SCOPED_TRACE("RectangularRegion");
    check(expected.northwest, actual.northwest);
    check(expected.southeast, actual.southeast);
}

inline void check(std::list<RectangularRegion> expected, std::list<RectangularRegion> actual)
{
    SCOPED_TRACE("list<RectangularRegion>");
    ASSERT_EQ(expected.size(), actual.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        SCOPED_TRACE(boost::format("Rectangle #%1%") % i);
        check(expected.front(), actual.front());
        expected.pop_front();
        actual.pop_front();
    }
}

inline void check(PolygonalRegion expected, PolygonalRegion actual)
{
    SCOPED_TRACE("PolygonalRegion");
    ASSERT_EQ(expected.size(), actual.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        SCOPED_TRACE(boost::format("Coordinate #%1%") % i);
        check(expected.front(), actual.front());
        expected.pop_front();
        actual.pop_front();
    }
}

inline void check(const IdentifiedRegion& expected, const IdentifiedRegion& actual)
{
    EXPECT_EQ(expected.region_dictionary, actual.region_dictionary);
    EXPECT_EQ(expected.region_identifier, actual.region_identifier);
    EXPECT_EQ(expected.local_region, actual.local_region);
}

inline void check(const GeographicRegion& expected, const GeographicRegion& actual)
{
    ASSERT_EQ(get_type(expected), get_type(actual));
    boost::apply_visitor(check_visitor<GeographicRegion>(), expected, actual);
}

} // namespace security
} // namespace vanetza

#endif /* CHECK_REGION_HPP_UFSV2RZ5 */

