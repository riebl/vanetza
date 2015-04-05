#include <gtest/gtest.h>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;

std::list<Payload> serialize(std::list<Payload> p) {
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, p);
    InputArchive ia(stream);
    std::list<Payload> deP;
    deserialize(ia, deP);
    return deP;
}

TEST(Payload, Serialize) {
    Payload p;
    Unsecured u;
    for (int c = 0; c < 12; c++) {
        u.push_back(c);
    }
    p = u;

    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, p);
    InputArchive ia(stream);
    Payload deP;
    deserialize(ia, deP);

    EXPECT_EQ(boost::get<Unsecured>(p), boost::get<Unsecured>(deP));
}

TEST(PayloadList, Serialize) {
    std::list<Payload> list = setPayload_List();
    std::list<Payload> deList = serialize(list);

    testPayload_list(list, deList);
}
