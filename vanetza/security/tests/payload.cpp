#include <gtest/gtest.h>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;

std::list<Payload> serialize(const std::list<Payload>& p)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, p);
    InputArchive ia(stream);
    std::list<Payload> deP;
    deserialize(ia, deP);
    return deP;
}

TEST(Payload, Serialize)
{
    Payload p;
    p.type = PayloadType::Unsecured;
    for (int c = 0; c < 12; c++) {
        p.buffer.push_back(c);
    }
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, p);
    InputArchive ia(stream);
    Payload deP;
    deserialize(ia, deP);

    EXPECT_EQ(p.buffer, deP.buffer);
}

TEST(Payload, Serialize_List)
{
    std::list<Payload> list = setPayload_List();
    std::list<Payload> deList = serialize(list);

    testPayload_list(list, deList);
}

TEST(Payload, WebValidator_Size)
{
    std::list<Payload> list;
    Payload p;
    p.buffer = {{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }};
    list.push_back(p);

    EXPECT_EQ(10, get_size(list));
}
