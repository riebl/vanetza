#include <gtest/gtest.h>
#include <vanetza/common/bit_number.hpp>
#include <vanetza/security/validity_restriction.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza;
using namespace security;
using namespace std;

TEST(Duration, Duration) {
    uint16_t a = 0x8007;    // 1000000000000007
    uint16_t b = 7;

    Duration dur(b, Duration::Units::Years);
    Duration dur2(a);

    EXPECT_EQ(dur.raw(), a);
    EXPECT_EQ(dur2.raw(), a);
}

TEST(ValidityRestriction, Serialization) {
    std::list<ValidityRestriction> list;
    list.push_back(setValidityRestriction_Time_End());
    list.push_back(setValidityRestriction_Time_Start_And_End());
    list.push_back(setValidityRestriction_Time_Start_And_Duration());
    list.push_back(setValidityRestriction_Region());

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, list);

    std::list<ValidityRestriction> delist;
    InputArchive ia(stream);
    deserialize(ia, delist);

    auto it1 = delist.begin();
    auto it2 = list.begin();

    testValidityRestriction_Time_End(*it2++, *it1++);
    testValidityRestriction_Time_Start_And_End(*it2++, *it1++);
    testValidityRestriction_Time_Start_And_Duration(*it2++, *it1++);
    testValidityRestriction_Region(*it2++, *it1++);
}
