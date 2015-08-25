#include <gtest/gtest.h>
#include <vanetza/security/region.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

GeographicRegion serialize(GeographicRegion reg)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, reg);
    GeographicRegion dereg;
    InputArchive ia(stream);
    size_t size = deserialize(ia, dereg);
    EXPECT_EQ(get_size(dereg), size);
    return dereg;
}

TEST(Region, Serialize_CircularRegion)
{
    GeographicRegion reg = setGeographicRegion_CircularRegion();
    GeographicRegion deReg = serialize(reg);
    testGeographicRegion_CircularRegion(reg, deReg);
}

TEST(Region, Serialize_IdentifiedRegion)
{
    GeographicRegion reg = setGeographicRegion_IdentifiedRegion();
    GeographicRegion dereg = serialize(reg);
    testGeographicRegion_IdentifiedRegion(reg, dereg);
}

TEST(Region, Serialize_PolygonalRegion)
{
    GeographicRegion reg = setGeographicRegion_PolygonalRegion();
    GeographicRegion dereg = serialize(reg);
    testGeographicRegion_PolygonalRegion(reg, dereg);

}

TEST(Region, Serialize_RectangularRegion_list)
{
    GeographicRegion reg = setGeographicRegion_RectangularRegion_list();
    GeographicRegion dereg = serialize(reg);
    testGeographicRegion_RectangularRegion_list(reg, dereg);
}
