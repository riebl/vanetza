#include <gtest/gtest.h>
#include <vanetza/security/region.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

GeograpicRegion serialize(GeograpicRegion reg) {
    std:stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, reg);
    GeograpicRegion dereg;
    InputArchive ia(stream);
    deserialize(ia, dereg);
    return dereg;
}

TEST(Region, Serialize_CircularRegion) {
    GeograpicRegion reg = setGeograpicRegion_CircularRegion();
    GeograpicRegion deReg = serialize(reg);
    testGeograpicRegion_CircularRegion(reg, deReg);
}

TEST(Region, Serialize_IdentifiedRegion) {
    GeograpicRegion reg = setGeograpicRegion_IdentifiedRegion();
    GeograpicRegion dereg = serialize(reg);
    testGeograpicRegion_IdentifiedRegion(reg, dereg);
}

TEST(Region, Serialize_PolygonalRegion) {
    GeograpicRegion reg = setGeograpicRegion_PolygonalRegion();
    GeograpicRegion dereg = serialize(reg);
    testGeograpicRegion_PolygonalRegion(reg, dereg);

}

TEST(Region, Serialize_RectangularRegion_list) {
    GeograpicRegion reg = setGeograpicRegion_RectangularRegion_list();
    GeograpicRegion dereg = serialize(reg);
    testGeograpicRegion_RectangularRegion_list(reg, dereg);
}
