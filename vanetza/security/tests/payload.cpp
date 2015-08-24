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

TEST(PayloadList, Serialize)
{
    std::list<Payload> list = setPayload_List();
    std::list<Payload> deList = serialize(list);

    testPayload_list(list, deList);
}

TEST(WebValidator, Size)
{
    std::list<Payload> list;
    Payload p;

    char str[] = "0123456789ABCDEF";
    int n;
    for (int i = 0; i < 8; i++) {
        sscanf(str + 2 * i, "%2X", &n);
        p.buffer.push_back((char) n);
    }
    list.push_back(p);

    EXPECT_EQ(10, get_size(list));
}
