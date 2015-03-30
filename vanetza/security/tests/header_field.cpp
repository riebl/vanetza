#include <gtest/gtest.h>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/certificate.hpp>
#include <vanetza/geonet/units.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace std;
using namespace vanetza::security;
using namespace vanetza;

std::list<HeaderField> serialize(std::list<HeaderField> list) {
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);
    std::list<HeaderField> deList;
    InputArchive ia(stream);
    deserialize(ia, deList);
    return deList;
}

TEST(HeaderField, Serialize) {
    std::list<HeaderField> list = setHeaderField_list();
    std::list<HeaderField> deList = serialize(list);
    testHeaderFieldList(list, deList);
}
